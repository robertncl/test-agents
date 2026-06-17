"""Core framework for the POC security-verification test agents.

This module is intentionally dependency-free (Python standard library only) so the
harness runs anywhere with ``python3`` and, where needed, ``docker``/``git`` on PATH.

Concepts
--------
Backend
    *Where* a probe command is executed. ``DockerBackend`` execs into the sandbox
    container under test, ``HostBackend`` runs on the local machine (used for the
    git-worktree and file-permission tests), and ``ManualBackend`` never executes —
    it forces a ``BLOCKED`` result with documented manual steps for controls that
    require a live GitHub/Intune tenant.

Probe
    A single observable action with a *security expectation*: ``secure_when="fail"``
    means a correctly-isolated sandbox should make the command fail (non-zero exit),
    e.g. an attempt to reach the network. ``secure_when="succeed"`` means the command
    should succeed (e.g. reaching an allowlisted host).

TestAgent
    One POC test case. ``execute`` returns a :class:`TestResult` carrying status,
    per-probe evidence, and (for manual cases) the verification steps. Agents register
    themselves with :func:`register` so the CLI can discover them.
"""

from __future__ import annotations

import abc
import dataclasses
import datetime
import enum
import shutil
import subprocess
from dataclasses import field
from typing import Optional

UTC = datetime.timezone.utc


def now_iso() -> str:
    """UTC timestamp, second precision — used for evidence rows."""
    return datetime.datetime.now(UTC).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #
class Status(str, enum.Enum):
    PASS = "PASS"        # control behaved as the plan's "Expected (pass) result"
    FAIL = "FAIL"        # a bypass / insecure behaviour was observed
    BLOCKED = "BLOCKED"  # could not execute (missing live tenant / docker / prereq)
    ERROR = "ERROR"      # the agent itself failed unexpectedly

    def __str__(self) -> str:  # nicer table output
        return self.value


# --------------------------------------------------------------------------- #
# Command execution
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class CommandOutcome:
    """Result of attempting to run one command via a backend."""

    exit_code: Optional[int]
    stdout: str
    stderr: str
    executed: bool          # False => backend declined/could not run it
    error: str = ""

    @property
    def failed(self) -> bool:
        """True if the command ran and returned a non-zero exit code."""
        return self.executed and self.exit_code not in (0,)

    def to_dict(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "executed": self.executed,
            "stdout": _clip(self.stdout),
            "stderr": _clip(self.stderr),
            "error": self.error,
        }


def _clip(text: str, limit: int = 2000) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


def _run(command: list[str], cwd: Optional[str] = None, timeout: int = 20,
         env: Optional[dict] = None) -> CommandOutcome:
    """Run a command, never raising — failures are returned as data."""
    try:
        proc = subprocess.run(
            command, cwd=cwd, env=env,
            capture_output=True, text=True, timeout=timeout,
        )
        return CommandOutcome(proc.returncode, proc.stdout, proc.stderr, executed=True)
    except FileNotFoundError as exc:
        return CommandOutcome(None, "", str(exc), executed=False, error=f"not found: {command[0]}")
    except subprocess.TimeoutExpired as exc:
        return CommandOutcome(
            None, exc.stdout or "", (exc.stderr or "") + "\n[timeout]",
            executed=True, error="timeout",
        )


# --------------------------------------------------------------------------- #
# Backends
# --------------------------------------------------------------------------- #
class Backend(abc.ABC):
    kind = "base"

    def available(self) -> bool:
        return True

    @abc.abstractmethod
    def exec(self, command: list[str], timeout: int = 20) -> CommandOutcome:
        ...

    def describe(self) -> str:
        return self.kind


class HostBackend(Backend):
    """Run on the local machine. Used by SC-09 (git worktrees) and SC-12 (file perms)."""

    kind = "host"

    def __init__(self, cwd: Optional[str] = None):
        self.cwd = cwd

    def exec(self, command: list[str], timeout: int = 20) -> CommandOutcome:
        return _run(command, cwd=self.cwd, timeout=timeout)


class DockerBackend(Backend):
    """Exec probe commands inside the sandbox container under test."""

    kind = "docker"

    def __init__(self, container: str):
        self.container = container

    def available(self) -> bool:
        if not shutil.which("docker"):
            return False
        out = _run(["docker", "inspect", "-f", "{{.State.Running}}", self.container], timeout=10)
        return out.executed and out.exit_code == 0 and out.stdout.strip() == "true"

    def exec(self, command: list[str], timeout: int = 20) -> CommandOutcome:
        return _run(["docker", "exec", self.container, *command], timeout=timeout)

    def describe(self) -> str:
        return f"docker:{self.container}"


class ManualBackend(Backend):
    """Never executes. Forces BLOCKED + documented manual verification steps."""

    kind = "manual"

    def available(self) -> bool:
        return False

    def exec(self, command: list[str], timeout: int = 20) -> CommandOutcome:
        return CommandOutcome(None, "", "", executed=False, error="manual backend: not executed")


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Probe:
    name: str
    description: str
    command: list[str]
    secure_when: str = "fail"   # "fail" | "succeed"
    rationale: str = ""

    def __post_init__(self):
        if self.secure_when not in ("fail", "succeed"):
            raise ValueError("secure_when must be 'fail' or 'succeed'")


@dataclasses.dataclass
class ProbeResult:
    probe: Probe
    outcome: CommandOutcome
    secure: Optional[bool]   # True=secure behaviour, False=insecure, None=undetermined
    detail: str = ""

    @property
    def label(self) -> str:
        if self.secure is True:
            return "secure"
        if self.secure is False:
            return "INSECURE"
        return "undetermined"

    def to_dict(self) -> dict:
        return {
            "probe": self.probe.name,
            "description": self.probe.description,
            "command": self.probe.command,
            "secure_when": self.probe.secure_when,
            "result": self.label,
            "detail": self.detail,
            "outcome": self.outcome.to_dict(),
        }


def evaluate_probe(probe: Probe, outcome: CommandOutcome) -> ProbeResult:
    """Score one probe outcome against its security expectation."""
    if not outcome.executed:
        return ProbeResult(probe, outcome, secure=None,
                           detail=outcome.error or "not executed by backend")

    if probe.secure_when == "fail":
        secure = outcome.failed
        detail = ("blocked as expected" if secure
                  else "command SUCCEEDED — isolation/control did not hold")
    else:  # secure_when == "succeed"
        secure = not outcome.failed
        detail = ("succeeded as expected" if secure
                  else "command was blocked but was expected to succeed")
    return ProbeResult(probe, outcome, secure=secure, detail=detail)


# --------------------------------------------------------------------------- #
# Test result
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class TestResult:
    id: str
    group: int
    control: str
    expected: str
    must_pass: bool
    status: Status
    summary: str
    backend: str = ""
    probe_results: list[ProbeResult] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    notes: str = ""
    started: str = field(default_factory=now_iso)
    finished: str = field(default_factory=now_iso)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "group": self.group,
            "control": self.control,
            "expected": self.expected,
            "must_pass": self.must_pass,
            "status": self.status.value,
            "summary": self.summary,
            "backend": self.backend,
            "probe_results": [pr.to_dict() for pr in self.probe_results],
            "manual_steps": self.manual_steps,
            "evidence": self.evidence,
            "notes": self.notes,
            "started": self.started,
            "finished": self.finished,
        }

    def evidence_row(self, tester: str = "poc-harness") -> dict:
        """One row for Appendix C — Evidence log."""
        refs = "; ".join(self.evidence) if self.evidence else "(see JSON probe outcomes)"
        return {
            "Case ID": self.id,
            "Date": self.finished,
            "Tester": tester,
            "Result": self.status.value,
            "Evidence ref(s)": refs,
            "Notes": self.summary,
        }


# --------------------------------------------------------------------------- #
# Run context + agent base
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class RunContext:
    """Shared configuration passed to every agent's ``execute``."""

    backend_choice: str = "auto"      # auto | docker | host | manual
    container: str = "copilot-sandbox"
    workspace: str = "/workspace"
    allowlist: tuple[str, ...] = ("github.com", "api.github.com", "objects.githubusercontent.com")
    simulate: bool = False
    tester: str = "poc-harness"
    extra: dict = field(default_factory=dict)

    def docker_backend(self) -> DockerBackend:
        return DockerBackend(self.container)


class TestAgent(abc.ABC):
    """Base class for one POC test case.

    Subclasses set the metadata class attributes and implement :meth:`execute`.
    """

    id: str = ""
    group: int = 0
    control: str = ""
    method: str = ""
    expected: str = ""
    must_pass: bool = True
    requires: str = ""   # human-readable prerequisites

    @abc.abstractmethod
    def execute(self, ctx: RunContext) -> TestResult:
        ...

    # -- helpers ---------------------------------------------------------- #
    def result(self, status: Status, summary: str, *, backend: str = "",
               probe_results: Optional[list[ProbeResult]] = None,
               manual_steps: Optional[list[str]] = None,
               evidence: Optional[list[str]] = None,
               notes: str = "", started: Optional[str] = None) -> TestResult:
        return TestResult(
            id=self.id, group=self.group, control=self.control,
            expected=self.expected, must_pass=self.must_pass,
            status=status, summary=summary, backend=backend,
            probe_results=probe_results or [],
            manual_steps=manual_steps or [],
            evidence=evidence or [],
            notes=notes,
            started=started or now_iso(),
        )

    @staticmethod
    def run_probes(backend: Backend, probes: list[Probe], timeout: int = 20) -> list[ProbeResult]:
        return [evaluate_probe(p, backend.exec(p.command, timeout=timeout)) for p in probes]

    @staticmethod
    def aggregate(probe_results: list[ProbeResult]) -> Status:
        """PASS if every executed probe is secure and at least one executed; FAIL on
        any insecure probe; BLOCKED if nothing executed."""
        executed = [pr for pr in probe_results if pr.secure is not None]
        if not executed:
            return Status.BLOCKED
        if any(pr.secure is False for pr in executed):
            return Status.FAIL
        return Status.PASS


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
_REGISTRY: dict[str, type[TestAgent]] = {}


def register(cls: type[TestAgent]) -> type[TestAgent]:
    """Class decorator: add an agent to the global registry, keyed by its ``id``."""
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define a non-empty id")
    if cls.id in _REGISTRY:
        raise ValueError(f"duplicate agent id: {cls.id}")
    _REGISTRY[cls.id] = cls
    return cls


def all_agents() -> list[TestAgent]:
    return [cls() for _, cls in sorted(_REGISTRY.items())]


def get_agent(test_id: str) -> Optional[TestAgent]:
    cls = _REGISTRY.get(test_id.upper())
    return cls() if cls else None


def agents_by_group(group: int) -> list[TestAgent]:
    return [a for a in all_agents() if a.group == group]
