"""Data protection, residency & retention verification (DP-01..05). B.9.

Compliance-critical (gates GO vs GO-WITH-CONDITIONS per B.12) but not marked
must-pass in the bypass-critical sense; these are evidence-gathering verifications.
"""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

GROUP = "DP"

CASES = [
    TestCase(
        id="DP-01", group=GROUP, control="End-to-end data-flow map",
        method=["Map the data flow for each surface: completions, chat, CLI, cloud "
                "agent, code review, MCP."],
        commands=["# document trigger -> context assembly -> execution -> inference -> output -> audit"],
        expected="A complete, evidenced data-flow map exists for every surface (B.2 compliance).",
    ),
    TestCase(
        id="DP-02", group=GROUP, control="Residency position",
        preconditions=["GHE.com tenant region known (Australia/Japan nearest)"],
        method=["Evidence where repo/code data resides.",
                "Document categories GitHub may store/transfer outside the region per the DPA.",
                "Record that model inference/content filtering is NOT region-bound."],
        commands=["# evidence repo-data residency; cite DPA categories; note inference not region-bound"],
        expected="Documented residency position; no MY/SG residency region; inference "
                 "boundary explicitly stated.",
    ),
    TestCase(
        id="DP-03", group=GROUP, control="Retention table",
        method=["Confirm retention per surface."],
        commands=["# verify: IDE completions/chat = not retained; CLI ~28 days; "
                  "cloud/coding-agent session logs = life of account; engagement = 2 years"],
        expected="Retention table confirmed per surface and matches documentation.",
    ),
    TestCase(
        id="DP-04", group=GROUP, control="Content exclusion",
        preconditions=["Content-exclusion rules configurable at repo/org"],
        method=["Configure exclusions for sensitive paths.",
                "Verify completions/chat/agent context honour them."],
        commands=["# set content exclusion for ${excluded_path}; verify it is withheld from context/completions"],
        expected="Excluded paths are withheld from indexing/completions/agent context.",
    ),
    TestCase(
        id="DP-05", group=GROUP, control="PII handling",
        preconditions=["Synthetic PII-like data only"],
        method=["Using synthetic PII only, verify it is not retained/transmitted beyond "
                "expectation.",
                "Confirm DLP/secret-scanning coverage."],
        commands=["# seed synthetic PII; trace handling; confirm DLP/secret-scanning catches it"],
        expected="Synthetic PII not retained/transmitted beyond expectation; DLP/secret "
                 "scanning covers it.",
    ),
]

AGENT = Agent(
    key="data",
    name="Data Protection, Residency & Retention",
    group=GROUP,
    description="Data-flow map, residency position, retention table, content exclusion, "
                "and PII handling (B.9).",
    test_cases=CASES,
)
