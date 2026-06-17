"""Docker sandbox backend -- the runnable reference implementation.

This backend translates a :class:`~sandbox.policy.Policy` into ``docker run``
flags. It is the most portable of the three (Docker is everywhere) and the
security properties it enforces are real and verifiable:

  * **Host FS isolation** -- only the workspace is bind-mounted; the container
    root is its own image, so host paths outside the workspace are invisible.
  * **Read-only workspace** -- ``-v src:dst:ro``.
  * **Full network deny** -- ``--network none``.
  * **Hardening** -- ``--cap-drop ALL``, ``--security-opt no-new-privileges``,
    non-root user, pid/memory limits, read-only rootfs + tmpfs.

Per-host network allowlisting is *not* something plain Docker can do without an
egress proxy, so this backend does not advertise ``network-allowlist``;
scenarios needing it are skipped here and exercised on backends that do.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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

# A small image that ships both /bin/sh and python3 + busybox wget, so the
# filesystem / network / MCP probes can all run unmodified. Override with
# SANDBOX_TEST_IMAGE if you maintain your own agent image.
DEFAULT_IMAGE = os.environ.get("SANDBOX_TEST_IMAGE", "python:3.12-alpine")


class DockerBackend(Backend):
    name = "docker"
    capabilities = {CAP_FS_ISOLATION, CAP_FS_READONLY, CAP_NETWORK_DENY, CAP_MCP}

    def __init__(self, image: str = DEFAULT_IMAGE):
        self.image = image
        self.docker = os.environ.get("DOCKER_BIN", "docker")

    def is_available(self) -> tuple[bool, str]:
        if shutil.which(self.docker) is None:
            return False, f"{self.docker!r} not found on PATH"
        try:
            r = subprocess.run(
                [self.docker, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"docker not responding: {e}"
        if r.returncode != 0:
            return False, f"docker daemon unreachable: {r.stderr.strip()}"
        return True, f"docker {r.stdout.strip()}"

    # ------------------------------------------------------------------ #
    def load_native(self, policy_name: str) -> dict:
        """Load the docker-native policy document for ``policy_name``."""
        path = native_policy_path("docker", policy_name, "json")
        if not path.exists():
            raise FileNotFoundError(
                f"no docker-native policy for {policy_name!r} (expected {path})"
            )
        return json.loads(path.read_text())

    def _docker_args(self, policy: Policy, workspace: Path) -> list[str]:
        """Build ``docker run`` flags from the docker-native policy file.

        The static security posture (network mode, read-only rootfs, caps,
        tmpfs, workspace mode) comes from ``policies/docker/<name>.json``. Only
        runtime data is injected here: the host workspace path and any dynamic
        read/write path allowlist the scenario is exercising.
        """
        native = self.load_native(policy.name)
        args: list[str] = [self.docker, "run", "--rm", "-i"]

        for cap in native.get("cap_drop", []):
            args += ["--cap-drop", cap]
        for opt in native.get("security_opt", []):
            args += ["--security-opt", opt]
        if native.get("pids_limit"):
            args += ["--pids-limit", str(native["pids_limit"])]
        if native.get("mem_limit"):
            args += ["--memory", str(native["mem_limit"])]
        if native.get("user"):
            args += ["--user", str(native["user"])]
        if native.get("read_only"):
            args.append("--read-only")
        for target, opts in native.get("tmpfs", {}).items():
            args += ["--tmpfs", f"{target}:{opts}"]
        for k, v in native.get("environment", {}).items():
            args += ["-e", f"{k}={v}"]
        args += ["--network", native.get("network_mode", "none")]

        # workspace mount (mode declared natively) + dynamic allowlist mounts
        ws = native["workspace"]
        ro = ":ro" if ws.get("read_only") else ""
        args += ["-v", f"{workspace.resolve()}:{ws['target']}{ro}"]
        for p in policy.filesystem.read_paths:
            args += ["-v", f"{Path(p).resolve()}:{p}:ro"]
        for p in policy.filesystem.write_paths:
            args += ["-v", f"{Path(p).resolve()}:{p}"]
        args += ["-w", ws["target"]]

        return args

    def run(
        self,
        argv: list[str],
        *,
        policy: Policy,
        workspace: Path,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        cmd = self._docker_args(policy, workspace)
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        cmd += [self.image, *argv]

        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as e:
            return RunResult(
                returncode=124,
                stdout=(e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""),
                stderr=(e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or ""),
                timed_out=True,
                meta={"argv": cmd},
            )
        return RunResult(
            returncode=r.returncode,
            stdout=r.stdout,
            stderr=r.stderr,
            meta={"argv": cmd},
        )
