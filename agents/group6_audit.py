"""Group 6 - Auditability & monitoring (SC-23..26). B.7 Group 6. All must-pass."""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

GROUP = "G6"

CASES = [
    TestCase(
        id="SC-23", group=GROUP, control="Commit attribution & signing", must_pass=True,
        method=["Inspect agent commits."],
        commands=["git log --show-signature -n 5", "# check author=Copilot, human co-author, session-log link"],
        expected="Authored by Copilot, human co-author, signed, link to session log present.",
    ),
    TestCase(
        id="SC-24", group=GROUP, control="Agentic audit-log capture", must_pass=True,
        method=["Trigger a range of agent actions.",
                "Query the audit log + agent session filters."],
        commands=["# drive agent actions; query GitHub audit log + agent session filters"],
        expected="All relevant agentic events recorded and queryable.",
    ),
    TestCase(
        id="SC-25", group=GROUP, control="SIEM ingestion & alerting", must_pass=True,
        negative=True,
        preconditions=["Audit/agentic events streaming to Microsoft Sentinel"],
        method=["Stream audit/agentic events to Sentinel.",
                "Build an alert (firewall disabled / autopilot enabled / mass merge) and "
                "trigger the seeded condition."],
        commands=["# Sentinel: create analytic rule; then seed the condition and observe the alert"],
        expected="Events ingested; the alert fires on the seeded condition.",
    ),
    TestCase(
        id="SC-26", group=GROUP, control="Activity reporting", must_pass=True,
        method=["Download the Copilot activity report and usage metrics."],
        commands=["# export Copilot activity report + usage metrics; reconcile vs observed activity"],
        expected="Reports reconcile with observed activity.",
    ),
]

AGENT = Agent(
    key="group6",
    name="Group 6 - Auditability & Monitoring",
    group=GROUP,
    description="Commit attribution/signing, agentic audit-log capture, SIEM "
                "ingestion + alerting, and activity reporting.",
    test_cases=CASES,
)
