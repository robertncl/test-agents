#!/usr/bin/env python3
"""Example: run the GitHub Copilot agent inside each sandbox under a policy.

Mirrors the style of OpenShell's ``examples/`` -- a small driver that wires a
policy + workspace to a backend and launches the agent. The agent process is
the sandboxed command, so the file/network/MCP controls validated by the test
suite apply to the real agent too.

Run:
    pip install -r ../requirements.txt   # not needed; stdlib only
    GITHUB_TOKEN=... python examples/run_copilot_agent.py --backend docker \
        --prompt "List the files in this repo and summarise the README."

If the Copilot CLI is not installed/authenticated, the example reports that and
exits cleanly -- the security test suite does NOT depend on it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sandbox.agent import copilot_available, run_copilot_agent  # noqa: E402
from sandbox.backends import get_backend  # noqa: E402
from sandbox.policy import Policy  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="docker",
                    choices=["docker", "openshell", "copilot_local"])
    ap.add_argument("--policy", default="workspace-rw")
    ap.add_argument("--workspace", default=".",
                    help="host project directory shared into the sandbox")
    ap.add_argument("--prompt", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    backend = get_backend(args.backend)
    ok, reason = backend.is_available()
    if not ok:
        print(f"backend {args.backend!r} unavailable: {reason}")
        return 2

    ok, reason = copilot_available()
    if not ok:
        print(f"Copilot CLI not ready: {reason}")
        print("Set COPILOT_AGENT_CMD / COPILOT_BIN to point at your install.")
        return 2

    policy = Policy.load(args.policy)
    workspace = Path(args.workspace).resolve()
    print(f"Running Copilot agent in {args.backend} under policy "
          f"{policy.name!r}, workspace={workspace}")
    res = run_copilot_agent(
        backend, prompt=args.prompt, policy=policy,
        workspace=workspace, timeout=args.timeout,
    )
    print("---- stdout ----")
    print(res.stdout)
    if res.stderr.strip():
        print("---- stderr ----")
        print(res.stderr)
    print(f"---- exit {res.returncode}{' (timed out)' if res.timed_out else ''} ----")
    return res.returncode


if __name__ == "__main__":
    raise SystemExit(main())
