"""GitHub Copilot "local sandbox" backend.

When the GitHub Copilot CLI runs its agent on your machine, the shell commands
the agent issues are confined by the operating system's local sandbox
primitive -- ``sandbox-exec`` (Seatbelt) on macOS and a user namespace sandbox
(bubblewrap) on Linux. This backend models that local sandbox so the same
isolation / policy probes used for Docker can be evaluated against it.

Invocation can be fully overridden so it points at however your Copilot CLI is
wired up:

    COPILOT_SANDBOX_CMD   a template; ``{argv}`` is replaced with the probe
                          command, ``{workspace}`` with the mount point,
                          ``{policy}`` with a rendered policy file path.

If that env var is unset the backend falls back to the host OS primitive:
``bwrap`` on Linux, ``sandbox-exec`` on macOS.
"""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..policy import Policy, native_policy_path
from .base import (
    CAP_FS_ISOLATION,
    CAP_FS_READONLY,
    CAP_MCP,
    CAP_NETWORK_DENY,
    Backend,
    RunResult,
)


class CopilotLocalBackend(Backend):
    name = "copilot_local"
    capabilities = {CAP_FS_ISOLATION, CAP_FS_READONLY, CAP_NETWORK_DENY, CAP_MCP}

    def __init__(self):
        self.override = os.environ.get("COPILOT_SANDBOX_CMD")
        self.bwrap = os.environ.get("BWRAP_BIN", "bwrap")
        self.is_mac = platform.system() == "Darwin"

    # ------------------------------------------------------------------ #
    def is_available(self) -> tuple[bool, str]:
        if self.override:
            return True, "COPILOT_SANDBOX_CMD override"
        if self.is_mac:
            if shutil.which("sandbox-exec"):
                return True, "macOS sandbox-exec (Seatbelt)"
            return False, "sandbox-exec not found"
        if shutil.which(self.bwrap):
            return True, "bubblewrap (bwrap)"
        return False, (
            "no local sandbox primitive: install bubblewrap "
            "(`apt install bubblewrap`) or set COPILOT_SANDBOX_CMD"
        )

    # ------------------------------------------------------------------ #
    def _render_policy_file(self, policy: Policy, workspace: Path) -> Path:
        fd, path = tempfile.mkstemp(prefix="copilot-policy-", suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(
                {
                    "filesystem": {
                        "workspace": policy.filesystem.workspace,
                        "writable": policy.filesystem.workspace_writable,
                    },
                    "network": {
                        "default_deny": policy.network.default_deny,
                        "allow_hosts": policy.network.allow_hosts,
                    },
                    "mcp": {
                        "allow_servers": policy.mcp.allow_servers,
                        "servers": list(policy.mcp.effective_servers()),
                    },
                },
                fh,
                indent=2,
            )
        return Path(path)

    def _bwrap_args(self, policy: Policy, workspace: Path) -> list[str]:
        """Read the bubblewrap-native policy file and substitute runtime data.

        The static sandbox posture lives in
        ``policies/copilot_local/<name>.bwrap``; only the host workspace path and
        any dynamic read/write allowlist are injected here.
        """
        path = native_policy_path("copilot_local", policy.name, "bwrap")
        if not path.exists():
            raise FileNotFoundError(
                f"no bubblewrap-native policy for {policy.name!r} (expected {path})"
            )
        ws = str(workspace.resolve())
        args = [self.bwrap]
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            for tok in line.split():
                args.append(tok.replace("{workspace}", ws))

        # dynamic allowlist (the variable the scenario is exercising)
        for p in policy.filesystem.read_paths:
            args += ["--ro-bind", str(Path(p).resolve()), p]
        for p in policy.filesystem.write_paths:
            args += ["--bind", str(Path(p).resolve()), p]
        return args

    def _seatbelt_profile(self, policy: Policy, workspace: Path) -> str:
        """Read the Seatbelt-native (.sb) policy and substitute runtime data."""
        path = native_policy_path("copilot_local", policy.name, "sb")
        if not path.exists():
            raise FileNotFoundError(
                f"no Seatbelt-native policy for {policy.name!r} (expected {path})"
            )
        ws = str(workspace.resolve())
        text = path.read_text().replace("{workspace}", ws)
        extra = []
        for p in policy.filesystem.read_paths:
            extra.append(f'(allow file-read* (subpath "{Path(p).resolve()}"))')
        for p in policy.filesystem.write_paths:
            extra.append(f'(allow file-write* (subpath "{Path(p).resolve()}"))')
        if extra:
            text += "\n".join(extra) + "\n"
        return text

    # ------------------------------------------------------------------ #
    def run(
        self,
        argv: list[str],
        *,
        policy: Policy,
        workspace: Path,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        run_env = {**os.environ, **(env or {})}

        if self.override:
            policy_file = self._render_policy_file(policy, workspace)
            cmd_str = self.override.format(
                argv=shlex.join(argv),
                workspace=str(workspace.resolve()),
                policy=str(policy_file),
            )
            cmd = ["/bin/sh", "-c", cmd_str]
        elif self.is_mac:
            profile = self._seatbelt_profile(policy, workspace)
            fd, pf = tempfile.mkstemp(prefix="copilot-", suffix=".sb")
            with os.fdopen(fd, "w") as fh:
                fh.write(profile)
            cmd = ["sandbox-exec", "-f", pf, *argv]
        else:
            cmd = [*self._bwrap_args(policy, workspace), *argv]

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, env=run_env
            )
        except subprocess.TimeoutExpired as e:
            return RunResult(
                returncode=124,
                stdout=e.stdout or "" if isinstance(e.stdout, str) else "",
                stderr=e.stderr or "" if isinstance(e.stderr, str) else "",
                timed_out=True,
                meta={"argv": cmd},
            )
        return RunResult(
            returncode=r.returncode,
            stdout=r.stdout,
            stderr=r.stderr,
            meta={"argv": cmd},
        )
