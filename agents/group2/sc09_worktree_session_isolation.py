"""SC-09 — Worktree session isolation.

POC method: run two parallel agent sessions; attempt cross-session file/state access.
Expected (pass): sessions isolated; no cross-contamination.

Each Copilot agent session runs in its own git **worktree** (POC plan A.2/A.3). This
agent reproduces that isolation property concretely and runs it for real on the host:

  1. Create a throwaway git repo with a tracked file.
  2. Add two worktrees — "session A" and "session B".
  3. In A, make an uncommitted change and drop a secret file.
  4. Assert B does NOT see A's uncommitted change or secret (separate working trees).
  5. Assert each worktree is checked out on its own branch (no shared HEAD).

When a Docker target is also available, a second check confirms two sandbox
containers with separate volumes cannot read each other's workspace.
"""

from __future__ import annotations

import os
import shutil
import tempfile

from ..base import (
    HostBackend, ProbeResult, Probe, RunContext, Status, TestAgent, TestResult,
    evaluate_probe, register,
)

MANUAL_STEPS = [
    "In My Work, start two agent sessions in parallel on the same repo.",
    "In session A, have the agent create a file and make uncommitted edits.",
    "In session B, have the agent list the working tree and read A's file path.",
    "Confirm B cannot see A's uncommitted file/edits (separate worktrees).",
    "Confirm each session is on its own copilot/* branch with an independent HEAD.",
    "Capture both session-log IDs and the isolation evidence.",
]


@register
class SC09(TestAgent):
    id = "SC-09"
    group = 2
    control = "Worktree session isolation"
    method = "Run two parallel sessions; attempt cross-session file/state access."
    expected = "Sessions isolated; no cross-contamination."
    must_pass = True
    requires = "git on PATH (host worktree test). Docker optional for the volume-isolation check."

    def _git_worktree_check(self) -> list[ProbeResult]:
        """Build and tear down a real two-worktree repo, returning probe results."""
        root = tempfile.mkdtemp(prefix="sc09_")
        repo = os.path.join(root, "repo")
        wt_a = os.path.join(root, "session_a")
        wt_b = os.path.join(root, "session_b")
        host = HostBackend(cwd=repo)
        results: list[ProbeResult] = []
        try:
            os.makedirs(repo)
            # Minimal, identity-independent repo setup.
            setup = (
                "git init -q -b main . && "
                "git config user.email poc@example.com && "
                "git config user.name poc && "
                "printf 'base\\n' > shared.txt && "
                "git add shared.txt && git commit -qm init && "
                f"git worktree add -q -b session-a {wt_a} && "
                f"git worktree add -q -b session-b {wt_b}"
            )
            setup_out = host.exec(["bash", "-lc", setup], timeout=30)
            results.append(evaluate_probe(
                Probe("worktree-setup", "Create repo + two isolated worktrees",
                      ["bash", "-lc", "git worktree add ..."], secure_when="succeed",
                      rationale="Each session gets its own real working tree."),
                setup_out,
            ))
            if setup_out.failed or not setup_out.executed:
                return results

            # Session A makes an uncommitted change + drops a secret.
            HostBackend(cwd=wt_a).exec(
                ["bash", "-lc", "printf 'A-only\\n' >> shared.txt && "
                                "printf 'TOKEN=sk-a\\n' > secret_a.txt"], timeout=15)

            # B must not see A's secret file.
            b_sees_secret = HostBackend(cwd=wt_b).exec(
                ["bash", "-lc", "test -e secret_a.txt && echo LEAKED"], timeout=10)
            results.append(evaluate_probe(
                Probe("b-cannot-see-a-secret",
                      "Session B cannot see session A's uncommitted secret file",
                      ["bash", "-lc", "test -e secret_a.txt"], secure_when="fail",
                      rationale="Separate worktrees do not share uncommitted files."),
                b_sees_secret,
            ))

            # B's tracked file must be unchanged by A's edit.
            b_contaminated = HostBackend(cwd=wt_b).exec(
                ["bash", "-lc", "grep -q 'A-only' shared.txt && echo CONTAMINATED"], timeout=10)
            results.append(evaluate_probe(
                Probe("b-tracked-file-unchanged",
                      "Session A's edit does not leak into session B's working tree",
                      ["bash", "-lc", "grep 'A-only' shared.txt"], secure_when="fail",
                      rationale="Working-tree edits are per-worktree."),
                b_contaminated,
            ))

            # Each worktree on its own branch / independent HEAD.
            distinct = host.exec(
                ["bash", "-lc",
                 f"a=$(git -C {wt_a} rev-parse --abbrev-ref HEAD); "
                 f"b=$(git -C {wt_b} rev-parse --abbrev-ref HEAD); "
                 "test \"$a\" != \"$b\" && echo DISTINCT"], timeout=15)
            results.append(evaluate_probe(
                Probe("independent-heads",
                      "Each session is on its own branch (independent HEAD)",
                      ["bash", "-lc", "compare worktree branches"], secure_when="succeed",
                      rationale="No shared HEAD between concurrent sessions."),
                distinct,
            ))
            return results
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def _docker_volume_check(self, ctx: RunContext) -> list[ProbeResult]:
        """Optional: confirm two sandbox containers cannot read each other's volume."""
        from ..base import DockerBackend
        a, b = f"{ctx.container}-a", f"{ctx.container}-b"
        backend_a = DockerBackend(a)
        if not backend_a.available() or not DockerBackend(b).available():
            return []
        cross = backend_a.exec(
            ["bash", "-lc", f"cat {ctx.workspace}/../session_b/* 2>&1 | head -1"], timeout=15)
        return [evaluate_probe(
            Probe("cross-container-read",
                  "Session-A container cannot read session-B's workspace volume",
                  ["bash", "-lc", "read other session's volume"], secure_when="fail",
                  rationale="Per-session volumes are not shared across containers."),
            cross,
        )]

    def execute(self, ctx: RunContext) -> TestResult:
        if ctx.backend_choice == "manual":
            return self.result(
                Status.BLOCKED, "Manual mode: verify parallel-session isolation in My Work.",
                backend="manual", manual_steps=MANUAL_STEPS,
            )
        if not shutil.which("git"):
            return self.result(
                Status.BLOCKED, "git not found on PATH — cannot run the worktree isolation test.",
                backend="host", manual_steps=MANUAL_STEPS,
            )

        probe_results = self._git_worktree_check()
        probe_results += self._docker_volume_check(ctx)
        status = self.aggregate(probe_results)

        if status is Status.PASS:
            summary = "Parallel worktree sessions are isolated; no cross-session leakage."
        elif status is Status.FAIL:
            leaked = [pr.probe.name for pr in probe_results if pr.secure is False]
            summary = f"Cross-session contamination observed: {', '.join(leaked)}."
        else:
            summary = "Worktree isolation test could not be executed."

        evidence = [f"{pr.probe.name}={pr.label}" for pr in probe_results]
        return self.result(status, summary, backend="host(git)+docker(optional)",
                           probe_results=probe_results, evidence=evidence)
