"""Security-control scenarios.

Each scenario is an executable assertion about a sandbox: it sets up a policy,
runs a probe inside the sandbox via the backend, and decides PASS / FAIL.
Scenarios are defined *once* here and consumed by both the pytest suite
(``tests/``) and the standalone runner (``run_tests.py``).

Categories map to the three controls under test:

  host-fs-isolation  -- the host filesystem is invisible outside the workspace
  fs-policy          -- filesystem access follows the declared policy
  network-policy     -- egress follows the declared policy
  mcp-policy         -- only allowlisted MCP servers reach the agent
"""

from __future__ import annotations

import dataclasses
import secrets
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .backends.base import (
    CAP_FS_ISOLATION,
    CAP_FS_READONLY,
    CAP_MCP,
    CAP_NETWORK_ALLOWLIST,
    CAP_NETWORK_DENY,
    Backend,
    BackendUnavailable,
)
from .policy import FilesystemPolicy, Policy

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"
ERROR = "ERROR"


@dataclass
class Outcome:
    status: str
    message: str
    evidence: str = ""


def _pass(msg, evidence=""):
    return Outcome(PASS, msg, evidence)


def _fail(msg, evidence=""):
    return Outcome(FAIL, msg, evidence)


# --------------------------------------------------------------------------- #
# Scenario container
# --------------------------------------------------------------------------- #
@dataclass
class Scenario:
    key: str
    category: str
    title: str
    requires: tuple[str, ...]
    fn: Callable[[Backend, Path], Outcome]
    policy_name: str | None = None

    def evaluate(self, backend: Backend) -> Outcome:
        ok, reason = backend.is_available()
        if not ok:
            return Outcome(SKIP, f"{backend.name} unavailable: {reason}")
        for cap in self.requires:
            if not backend.supports(cap):
                return Outcome(
                    SKIP, f"{backend.name} does not enforce capability {cap!r}"
                )
        with tempfile.TemporaryDirectory(prefix=f"ws-{self.key}-") as ws:
            try:
                return self.fn(backend, Path(ws))
            except BackendUnavailable as e:
                return Outcome(SKIP, f"{backend.name} could not provision: {e}")
            except Exception as e:  # noqa: BLE001 - report, don't crash the matrix
                return Outcome(ERROR, f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# host filesystem isolation
# --------------------------------------------------------------------------- #
def _host_secret_invisible(backend: Backend, ws: Path) -> Outcome:
    """A secret file living on the host *outside* the workspace must not be
    readable from inside the sandbox."""
    policy = Policy.load("workspace-rw")
    token = secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix="host-secret-") as secret_dir:
        secret = Path(secret_dir) / "host_secret.txt"
        secret.write_text(f"TOPSECRET-{token}")
        res = backend.run_shell(
            f"cat {shlex.quote(str(secret))} 2>&1 || true",
            policy=policy,
            workspace=ws,
            timeout=60,
        )
    if token in res.stdout:
        return _fail(
            "host secret OUTSIDE the workspace was readable from the sandbox",
            res.stdout.strip(),
        )
    return _pass(
        "host secret outside the workspace is invisible to the sandbox",
        f"probe output: {res.stdout.strip()[:200]!r}",
    )


def _write_does_not_leak(backend: Backend, ws: Path) -> Outcome:
    """A write to a non-workspace path inside the sandbox must not appear on
    the host filesystem."""
    policy = Policy.load("workspace-rw")
    token = secrets.token_hex(8)
    host_path = Path(f"/tmp/sandbox_escape_{token}")
    if host_path.exists():
        host_path.unlink()
    backend.run_shell(
        f"echo LEAK-{token} > /tmp/sandbox_escape_{token} 2>&1 || true",
        policy=policy,
        workspace=ws,
        timeout=60,
    )
    leaked = host_path.exists() and token in host_path.read_text(errors="ignore")
    if host_path.exists():
        host_path.unlink()
    if leaked:
        return _fail("sandbox write escaped to the host at /tmp")
    return _pass("writes outside the workspace stay inside the sandbox")


def _workspace_is_shared(backend: Backend, ws: Path) -> Outcome:
    """Positive control: proves the workspace mount actually works, so the
    isolation results above are not a false positive from a broken mount."""
    policy = Policy.load("workspace-rw")
    token = secrets.token_hex(8)
    res = backend.run_shell(
        f"echo CANARY-{token} > {policy.filesystem.workspace}/canary.txt",
        policy=policy,
        workspace=ws,
        timeout=60,
    )
    canary = ws / "canary.txt"
    shared = canary.exists() and token in canary.read_text(errors="ignore")
    if not shared:
        return _fail(
            "workspace is not shared with the host -- mount is broken, "
            "isolation results are not trustworthy",
            res.stderr.strip(),
        )
    return _pass("workspace is correctly shared host<->sandbox")


# --------------------------------------------------------------------------- #
# filesystem policy
# --------------------------------------------------------------------------- #
def _readonly_blocks_write(backend: Backend, ws: Path) -> Outcome:
    policy = Policy.load("workspace-ro")
    res = backend.run_shell(
        f"echo nope > {policy.filesystem.workspace}/should_not_write 2>&1; "
        f"echo rc=$?",
        policy=policy,
        workspace=ws,
        timeout=60,
    )
    created = (ws / "should_not_write").exists()
    if created:
        return _fail("read-only workspace policy did not block the write")
    return _pass("read-only workspace policy blocked the write", res.stdout.strip())


def _readwrite_allows_write(backend: Backend, ws: Path) -> Outcome:
    policy = Policy.load("workspace-rw")
    token = secrets.token_hex(8)
    backend.run_shell(
        f"echo OK-{token} > {policy.filesystem.workspace}/wrote.txt",
        policy=policy,
        workspace=ws,
        timeout=60,
    )
    f = ws / "wrote.txt"
    if f.exists() and token in f.read_text(errors="ignore"):
        return _pass("read-write workspace policy permitted the write")
    return _fail("read-write workspace policy unexpectedly blocked the write")


def _read_allowlist_honored(backend: Backend, ws: Path) -> Outcome:
    """An extra host file granted via the read allowlist is readable; a sibling
    that was NOT granted stays invisible."""
    token = secrets.token_hex(8)
    with tempfile.TemporaryDirectory(prefix="extra-") as extra:
        allowed = Path(extra) / "allowed.txt"
        secret = Path(extra) / "secret.txt"
        allowed.write_text(f"ALLOWED-{token}")
        secret.write_text(f"SECRET-{token}")

        base = Policy.load("workspace-rw")
        policy = dataclasses.replace(
            base,
            filesystem=dataclasses.replace(
                base.filesystem, read_paths=[str(allowed)]
            ),
        )
        res_allowed = backend.run_shell(
            f"cat {shlex.quote(str(allowed))} 2>&1 || true",
            policy=policy, workspace=ws, timeout=60,
        )
        res_secret = backend.run_shell(
            f"cat {shlex.quote(str(secret))} 2>&1 || true",
            policy=policy, workspace=ws, timeout=60,
        )

    can_read_allowed = token in res_allowed.stdout
    can_read_secret = token in res_secret.stdout
    if can_read_allowed and not can_read_secret:
        return _pass("read allowlist honored: granted path readable, sibling denied")
    if not can_read_allowed:
        return _fail("allowlisted read path was NOT readable", res_allowed.stdout.strip())
    return _fail("non-allowlisted sibling file was readable", res_secret.stdout.strip())


# --------------------------------------------------------------------------- #
# network policy
# --------------------------------------------------------------------------- #
# Portable egress probe: works whether the image ships wget, curl, or only
# python3. Prints REACHED on success, BLOCKED on any failure/timeout.
_NET_PROBE = (
    "if command -v wget >/dev/null 2>&1; then "
    "  wget -T 5 -q -O - http://{host}/ >/dev/null 2>&1; "
    "elif command -v curl >/dev/null 2>&1; then "
    "  curl -s -m 5 http://{host}/ >/dev/null 2>&1; "
    "else "
    "  python3 -c 'import urllib.request,sys; urllib.request.urlopen(\"http://{host}/\",timeout=5)' >/dev/null 2>&1; "
    "fi && echo REACHED || echo BLOCKED"
)


def _default_deny_blocks_egress(backend: Backend, ws: Path) -> Outcome:
    policy = Policy.load("workspace-rw")  # network.default_deny, no allow_hosts
    res = backend.run_shell(
        _NET_PROBE.format(host="example.com"),
        policy=policy,
        workspace=ws,
        timeout=30,
    )
    if "REACHED" in res.stdout:
        return _fail("default-deny network policy did not block egress", res.stdout.strip())
    return _pass("default-deny network policy blocked all egress", res.stdout.strip())


def _allowlist_permits_only_listed(backend: Backend, ws: Path) -> Outcome:
    policy = Policy.load("net-allowlist")  # allow_hosts: [example.com]
    allowed = policy.network.allow_hosts[0]
    res_allowed = backend.run_shell(
        _NET_PROBE.format(host=allowed), policy=policy, workspace=ws, timeout=30
    )
    res_denied = backend.run_shell(
        _NET_PROBE.format(host="cloudflare.com"), policy=policy, workspace=ws, timeout=30
    )
    reached_allowed = "REACHED" in res_allowed.stdout
    reached_denied = "REACHED" in res_denied.stdout
    if reached_allowed and not reached_denied:
        return _pass(
            f"egress allowlist honored: {allowed} reachable, others blocked"
        )
    if not reached_allowed:
        return _fail(f"allowlisted host {allowed} was unreachable")
    return _fail("a non-allowlisted host was reachable")


# --------------------------------------------------------------------------- #
# MCP policy
# --------------------------------------------------------------------------- #
def _denied_mcp_stripped_from_config(backend: Backend, ws: Path) -> Outcome:
    """The policy's effective MCP config must contain only allowlisted servers."""
    policy = Policy.load("workspace-rw")
    effective = policy.mcp.effective_servers()
    denied = [s for s in policy.mcp.servers if s not in policy.mcp.allow_servers]
    leaked = [s for s in denied if s in effective]
    if leaked:
        return _fail(f"denied MCP server(s) present in effective config: {leaked}")
    if not policy.mcp.allow_servers:
        return _fail("policy fixture has no allowlisted MCP servers to validate")
    missing = [s for s in policy.mcp.allow_servers if s not in effective]
    if missing:
        return _fail(f"allowlisted MCP server(s) missing from config: {missing}")
    return _pass(
        f"effective MCP config exposes only {sorted(effective)}; "
        f"stripped {sorted(denied)}"
    )


def _denied_mcp_unreachable_in_sandbox(backend: Backend, ws: Path) -> Outcome:
    """The agent, reading the MCP config the backend renders into its workspace,
    sees only allowlisted servers -- verified from *inside* the sandbox."""
    policy = Policy.load("workspace-rw")
    import json

    from .agent import render_mcp_config

    cfg = ws / "mcp_effective.json"
    cfg.write_text(json.dumps(render_mcp_config(policy)))

    denied = next(
        (s for s in policy.mcp.servers if s not in policy.mcp.allow_servers), None
    )
    if denied is None:
        return Outcome(SKIP, "policy fixture has no denied MCP server to probe")

    res = backend.run_shell(
        f'grep -q {shlex.quote(denied)} {policy.filesystem.workspace}/mcp_effective.json '
        f'&& echo PRESENT || echo ABSENT',
        policy=policy,
        workspace=ws,
        timeout=60,
    )
    if "PRESENT" in res.stdout:
        return _fail(f"denied MCP server {denied!r} reachable in sandbox config")
    return _pass(f"denied MCP server {denied!r} absent from in-sandbox config")


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
SCENARIOS: list[Scenario] = [
    # host filesystem isolation
    Scenario("host-secret-invisible", "host-fs-isolation",
             "Host secret outside workspace is unreadable",
             (CAP_FS_ISOLATION,), _host_secret_invisible),
    Scenario("write-no-leak", "host-fs-isolation",
             "Sandbox writes do not leak to the host filesystem",
             (CAP_FS_ISOLATION,), _write_does_not_leak),
    Scenario("workspace-shared", "host-fs-isolation",
             "Workspace mount works (positive control)",
             (CAP_FS_ISOLATION,), _workspace_is_shared),
    # filesystem policy
    Scenario("ro-blocks-write", "fs-policy",
             "Read-only workspace policy blocks writes",
             (CAP_FS_READONLY,), _readonly_blocks_write),
    Scenario("rw-allows-write", "fs-policy",
             "Read-write workspace policy permits writes",
             (CAP_FS_ISOLATION,), _readwrite_allows_write),
    Scenario("read-allowlist", "fs-policy",
             "Filesystem read allowlist is honored",
             (CAP_FS_ISOLATION,), _read_allowlist_honored),
    # network policy
    Scenario("net-default-deny", "network-policy",
             "Default-deny network policy blocks all egress",
             (CAP_NETWORK_DENY,), _default_deny_blocks_egress),
    Scenario("net-allowlist", "network-policy",
             "Egress allowlist permits only listed hosts",
             (CAP_NETWORK_ALLOWLIST,), _allowlist_permits_only_listed),
    # mcp policy
    Scenario("mcp-config-gating", "mcp-policy",
             "Denied MCP servers stripped from effective config",
             (CAP_MCP,), _denied_mcp_stripped_from_config),
    Scenario("mcp-in-sandbox", "mcp-policy",
             "Denied MCP server absent from in-sandbox config",
             (CAP_MCP,), _denied_mcp_unreachable_in_sandbox),
]


def scenarios_for(category: str | None = None) -> list[Scenario]:
    if category is None:
        return list(SCENARIOS)
    return [s for s in SCENARIOS if s.category == category]


CATEGORIES = sorted({s.category for s in SCENARIOS})
