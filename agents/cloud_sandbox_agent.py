"""Copilot cloud sandbox agent (Azure Container Apps Sandboxes).

Covers POC plan s.5.2 (functional) and s.6.1 cloud-isolation cases:
TC-F-05..09, TC-S-04..07. Cloud sandbox is launched with `copilot --cloud`;
the CLI session runs in a fully isolated, ephemeral GitHub-hosted Linux
environment with an Active -> Stopped -> Deleted lifecycle.

Org gating (TC-S-08) and policy inheritance (TC-S-13) live in the Governance agent.
"""

from __future__ import annotations

from core.agent import Agent
from core.model import Priority as P
from core.model import TestCase

CASES = [
    TestCase(
        id="TC-F-05",
        priority=P.P1,
        title="Launch cloud sandbox",
        control="`copilot --cloud` provisions an ephemeral remote Linux session",
        theme="isolation",
        criterion="C6",
        method=["Run `copilot --cloud`; have it run a command revealing the host."],
        commands=["copilot --cloud", "# ask Copilot to run: hostname; cat /etc/os-release; whoami"],
        pass_criteria="An ephemeral Linux session provisions; commands run remotely, not locally.",
    ),
    TestCase(
        id="TC-F-06",
        priority=P.P1,
        title="Session-state lifecycle",
        control="Active -> Stop -> resume -> Delete behaves per docs",
        theme="isolation",
        criterion="C6",
        method=[
            "Create state, Stop the session, resume it, then Delete it.",
            "After Delete, attempt to resume.",
        ],
        commands=[
            "# write a marker file + export an env var; stop; resume; verify restored; delete; attempt resume",
        ],
        pass_criteria=(
            "On resume, files/env/in-progress work are restored from snapshot; after "
            "Delete the session and snapshot are unrecoverable."
        ),
    ),
    TestCase(
        id="TC-F-07",
        priority=P.P2,
        title="Cross-device continuity",
        control="A session resumes on a second device",
        theme="isolation",
        criterion="C6",
        method=["Start on device A, resume the same session on device B."],
        commands=["# device A: copilot --cloud (create state)", "# device B: resume session"],
        pass_criteria="Session resumes on B without copying files or reinstalling deps.",
    ),
    TestCase(
        id="TC-F-08",
        priority=P.P2,
        title="Parallel sessions",
        control=">=3 concurrent cloud sessions run independently",
        theme="isolation",
        criterion="C6",
        method=["Launch 3+ concurrent cloud sessions; run distinct workloads in each."],
        commands=["# launch 3 sessions; verify independent execution"],
        pass_criteria="Each session runs independently; no shared local resource contention.",
    ),
    TestCase(
        id="TC-F-09",
        priority=P.P2,
        title="Billing-meter sanity",
        control="Compute/memory/storage meters are visible and plausible",
        theme="audit",
        criterion="C6",
        method=["Run a known workload; capture compute/memory/snapshot-storage usage."],
        commands=["# run a fixed workload; export usage from billing/metering view"],
        pass_criteria="Metered usage is visible and plausibly matches the published meters.",
    ),
    TestCase(
        id="TC-S-04",
        priority=P.P1,
        title="Cloud session -> local isolation",
        control="A cloud session cannot reach the developer machine",
        theme="isolation",
        criterion="C1",
        method=["From the cloud sandbox, attempt to reach local files/network/services."],
        commands=[
            "# ask Copilot (in --cloud) to read a local-only path / connect to localhost services on the dev box",
        ],
        pass_criteria="No access to the developer machine from the cloud session.",
    ),
    TestCase(
        id="TC-S-05",
        priority=P.P1,
        title="Cloud session -> session isolation",
        control="One cloud session cannot observe/reach another",
        theme="isolation",
        criterion="C1",
        method=[
            "Run sessions A and B concurrently.",
            "From A, attempt to read B's files, processes, or network.",
        ],
        commands=["# from session A: enumerate other sessions' files/PIDs/network"],
        pass_criteria="Full isolation between concurrent sessions.",
    ),
    TestCase(
        id="TC-S-06",
        priority=P.P1,
        title="Ephemerality / residue",
        control="Deleted-session state does not survive into a fresh session",
        theme="isolation",
        criterion="C1",
        method=["Write a marker in a session, Delete it, provision a fresh session, look for residue."],
        commands=["# session1: echo MARKER > /tmp/marker ; delete", "# session2: search for MARKER"],
        pass_criteria="No residual artifacts or state from the deleted session.",
    ),
    TestCase(
        id="TC-S-07",
        priority=P.P2,
        title="Snapshot data-at-rest",
        control="Stopped-session snapshot scope matches docs; no unexpected secret retention",
        theme="isolation",
        criterion="C1",
        method=[
            "Stop a session that holds env vars/marker secrets.",
            "Inspect what the snapshot retains; confirm region/residency.",
        ],
        commands=["# stop session; review snapshot contents/metadata and storage region"],
        pass_criteria=(
            "Snapshot scope matches documentation; no unexpected secret retention; "
            "data residency is acceptable."
        ),
    ),
]

AGENT = Agent(
    key="cloud",
    name="Copilot Cloud Sandbox Agent (Azure Container Apps)",
    surface="Copilot cloud sandbox (Azure Container Apps Sandboxes)",
    description=(
        "Functional launch/lifecycle/continuity/parallelism/metering plus cloud "
        "isolation (local, cross-session, ephemerality, snapshot-at-rest)."
    ),
    test_cases=CASES,
)
