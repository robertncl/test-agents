"""NVIDIA OpenShell backend.

OpenShell (https://github.com/NVIDIA/OpenShell) is a gateway-backed sandbox
runtime for AI agents. Unlike a local bind-mounted container, an OpenShell
sandbox is a managed, provider-hosted container governed by a landlock-based
policy; you don't share host paths into it, you *upload* a workspace and
*download* results. The CLI lifecycle this backend drives is the real one:

    openshell sandbox create --name <n> --from <image> -- sleep infinity
    openshell sandbox exec   -n <n> -- mkdir -p <workdir>
    openshell sandbox upload  <n> <host-workspace> <workdir>
    openshell policy set      <n> --policy <policy.yaml> --wait
    openshell sandbox exec   -n <n> --workdir <workdir> -- <argv...>
    openshell sandbox download <n> <workdir> <host-workspace>
    openshell sandbox delete  <n>

Because every sandbox is a fresh managed container, host filesystem isolation is
structural: nothing on the host is reachable unless explicitly uploaded.

Configuration (env):
    OPENSHELL_BIN      openshell binary (default "openshell")
    OPENSHELL_FROM     base image for sandboxes (default "python:3.12-slim").
                       Point this at an OpenShell community image
                       (e.g. "python") in an environment that can pull it.
    OPENSHELL_WORKDIR  workspace dir inside the sandbox (default "/workspace")

If a sandbox cannot be provisioned (no pullable image, restart loop, etc.) the
backend raises ``BackendUnavailable`` so scenarios SKIP instead of failing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from ..policy import Policy, native_policy_path
from .base import (
    CAP_FS_ISOLATION,
    CAP_FS_READONLY,
    CAP_MCP,
    CAP_NETWORK_ALLOWLIST,
    CAP_NETWORK_DENY,
    Backend,
    BackendUnavailable,
    RunResult,
)

_PROVISION_ERRORS = (
    "error phase",
    "ContainerRestarting",
    "ImagePullFailed",
    "denied",
    "not ready",
)

# Remember images that fail to provision so the matrix doesn't retry a doomed
# `sandbox create` (~10s) for every scenario -- the first failure is enough.
_UNPROVISIONABLE: dict[str, str] = {}


class OpenShellBackend(Backend):
    name = "openshell"
    # OpenShell's policy engine does landlock FS confinement, per-endpoint egress
    # allowlists, and MCP gating, so it advertises the full capability set.
    capabilities = {
        CAP_FS_ISOLATION,
        CAP_FS_READONLY,
        CAP_NETWORK_DENY,
        CAP_NETWORK_ALLOWLIST,
        CAP_MCP,
    }

    def __init__(self):
        self.bin = os.environ.get("OPENSHELL_BIN", "openshell")
        self.image = os.environ.get("OPENSHELL_FROM", "python:3.12-slim")
        self.workdir = os.environ.get("OPENSHELL_WORKDIR", "/workspace")

    # ------------------------------------------------------------------ #
    def _cli(self, *args: str, timeout: int = 120, input_text: str | None = None):
        return subprocess.run(
            [self.bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )

    def is_available(self) -> tuple[bool, str]:
        if shutil.which(self.bin) is None:
            return False, f"{self.bin!r} not found on PATH -- install OpenShell"
        try:
            r = self._cli("status", timeout=20)
        except (subprocess.TimeoutExpired, OSError) as e:
            return False, f"openshell gateway not responding: {e}"
        if "Connected" not in (r.stdout + r.stderr):
            return False, "no OpenShell gateway connected (`openshell status`)"
        return True, f"openshell gateway connected (image={self.image})"

    # ------------------------------------------------------------------ #
    def render_policy_yaml(self, policy: Policy) -> str:
        """Render the OpenShell-native policy YAML for ``policy``.

        Matches the schema OpenShell reports for an effective policy:
        ``filesystem_policy`` (landlock read_only / read_write path lists),
        ``process``, and a network section built from the egress allowlist.
        """
        fs = policy.filesystem
        net = policy.network
        ro = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"]
        rw = ["/tmp"]
        if fs.workspace_writable:
            rw.append(self.workdir)
        else:
            ro.append(self.workdir)

        lines = [
            "version: 1",
            "filesystem_policy:",
            "  include_workdir: true",
            "  read_only:",
            *[f"  - {p}" for p in ro],
            "  read_write:",
            *[f"  - {p}" for p in rw],
            "landlock:",
            "  compatibility: best_effort",
            "process:",
            "  run_as_user: sandbox",
            "  run_as_group: sandbox",
            "network_policy:",
            f"  default: {'deny' if net.default_deny else 'allow'}",
            "  endpoints:",
        ]
        for host in net.allow_hosts:
            for port in net.allow_ports:
                lines.append(f"  - {host}:{port}:read-write:rest:enforce")
        if not net.allow_hosts:
            lines[-1] = "  endpoints: []"
        return "\n".join(lines) + "\n"

    def _policy_file(self, policy: Policy) -> Path:
        """Native YAML under policies/openshell/<name>.yaml, else rendered."""
        native = native_policy_path("openshell", policy.name, "yaml")
        text = native.read_text() if native.exists() else self.render_policy_yaml(policy)
        text = text.replace("{workdir}", self.workdir)
        fd, path = tempfile.mkstemp(prefix="openshell-policy-", suffix=".yaml")
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        return Path(path)

    # ------------------------------------------------------------------ #
    def _create(self, name: str) -> None:
        if self.image in _UNPROVISIONABLE:
            raise BackendUnavailable(_UNPROVISIONABLE[self.image])
        try:
            r = self._cli(
                "sandbox", "create", "--name", name,
                "--from", self.image, "--", "sleep", "infinity",
                timeout=180,
            )
        except subprocess.TimeoutExpired as e:
            raise BackendUnavailable(f"create timed out: {e}") from e
        blob = r.stdout + r.stderr
        if r.returncode != 0 or any(s in blob for s in _PROVISION_ERRORS):
            reason = (
                f"sandbox image {self.image!r} did not provision "
                f"(set OPENSHELL_FROM to a community image): {blob.strip()[:300]}"
            )
            _UNPROVISIONABLE[self.image] = reason
            raise BackendUnavailable(reason)

    def _delete(self, name: str) -> None:
        try:
            self._cli("sandbox", "delete", name, timeout=60)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def run(
        self,
        argv: list[str],
        *,
        policy: Policy,
        workspace: Path,
        timeout: int = 60,
        env: dict[str, str] | None = None,
    ) -> RunResult:
        name = f"sectest-{uuid.uuid4().hex[:10]}"
        policy_file = self._policy_file(policy)
        self._create(name)
        try:
            # stage the workspace inside the sandbox
            self._cli("sandbox", "exec", "-n", name, "--",
                      "mkdir", "-p", self.workdir, timeout=60)
            self._cli("sandbox", "upload", "--no-git-ignore",
                      name, str(workspace.resolve()), self.workdir, timeout=120)
            # apply the native policy and wait for it to load
            pr = self._cli("policy", "set", name, "--policy", str(policy_file),
                           "--wait", timeout=90)
            if pr.returncode != 0:
                raise BackendUnavailable(f"policy set failed: {pr.stderr.strip()[:300]}")

            exec_args = ["sandbox", "exec", "-n", name, "--workdir", self.workdir,
                         "--timeout", str(timeout)]
            for k, v in (env or {}).items():
                exec_args += ["--env", f"{k}={v}"]
            exec_args += ["--", *argv]
            try:
                r = self._cli(*exec_args, timeout=timeout + 30)
            except subprocess.TimeoutExpired as e:
                return RunResult(124, e.stdout or "", e.stderr or "", timed_out=True,
                                 meta={"sandbox": name})

            # reflect any writes back onto the host workspace
            self._sync_down(name, workspace)
            return RunResult(r.returncode, r.stdout, r.stderr,
                             meta={"sandbox": name, "policy_file": str(policy_file)})
        finally:
            self._delete(name)

    def _sync_down(self, name: str, workspace: Path) -> None:
        """Download the sandbox workdir back onto the host workspace dir."""
        with tempfile.TemporaryDirectory(prefix="oshell-dl-") as tmp:
            r = self._cli("sandbox", "download", name, self.workdir, tmp, timeout=120)
            if r.returncode != 0:
                return
            src = Path(tmp)
            # download may nest under a dir named like the workdir; flatten it.
            nested = src / Path(self.workdir).name
            root = nested if nested.is_dir() else src
            for item in root.iterdir():
                dest = workspace / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest)
