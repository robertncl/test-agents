"""Common backend interface.

Every backend knows how to take a :class:`~sandbox.policy.Policy` plus a host
workspace directory, launch a command (or the Copilot agent) inside an isolated
sandbox with that policy applied, and return the result.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path

from ..policy import Policy


class BackendUnavailable(Exception):
    """Raised by a backend when it cannot provision at *run* time.

    Distinct from ``is_available() == False`` (which is a cheap up-front check):
    this covers conditions only discoverable when actually launching, e.g. an
    OpenShell sandbox image that fails to provision. Scenarios translate it to
    SKIP rather than FAIL, since it reflects the environment, not the policy.
    """


@dataclass
class RunResult:
    """Outcome of running a command inside a sandbox."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    # Free-form details a backend wants to expose (e.g. the exact argv used).
    meta: dict | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def denied(self) -> bool:
        """True when the command was prevented from succeeding.

        A denial shows up as a non-zero exit or a timeout (e.g. a blocked
        network call that hangs then is killed).
        """
        return self.timed_out or self.returncode != 0


# Capabilities a scenario may require of a backend. If a backend does not
# support a capability, scenarios that need it are SKIPPED rather than failed.
CAP_FS_ISOLATION = "fs-isolation"          # bind-mount only the workspace
CAP_FS_READONLY = "fs-readonly"            # mount the workspace read-only
CAP_NETWORK_DENY = "network-deny"          # cut off all egress
CAP_NETWORK_ALLOWLIST = "network-allowlist"  # per-host egress allowlist
CAP_MCP = "mcp"                            # render/enforce an MCP allowlist


class Backend(abc.ABC):
    name: str = "base"

    # Capabilities this backend can actually enforce at runtime.
    capabilities: set[str] = set()

    @abc.abstractmethod
    def is_available(self) -> tuple[bool, str]:
        """Return ``(available, reason)``.

        ``available`` is False when the runtime/CLI isn't installed or not
        authenticated; ``reason`` is shown in SKIP messages.
        """

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    @abc.abstractmethod
    def run(
        self,
        argv: list[str],
        *,
        policy: Policy,
        workspace: Path,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        """Run ``argv`` inside the sandbox with ``policy`` enforced.

        ``workspace`` is a host directory bind-mounted as ``policy.filesystem
        .workspace`` inside the sandbox. Nothing else on the host may be
        reachable.
        """

    def run_shell(
        self,
        script: str,
        *,
        policy: Policy,
        workspace: Path,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        """Convenience: run a ``/bin/sh`` snippet inside the sandbox."""
        return self.run(
            ["/bin/sh", "-c", script],
            policy=policy,
            workspace=workspace,
            timeout=timeout,
            env=env,
        )
