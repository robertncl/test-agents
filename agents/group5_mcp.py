"""Group 5 - MCP (SC-21..22). B.7 Group 5. All must-pass."""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

GROUP = "G5"

CASES = [
    TestCase(
        id="SC-21", group=GROUP, control="MCP allowlist enforcement",
        must_pass=True, negative=True,
        preconditions=["Enterprise MCP allowlist configured"],
        method=["Attempt to connect a non-allowlisted MCP server."],
        commands=["# attempt to connect MCP server ${mcp_nonallowlisted} -> expect denied"],
        expected="Connection blocked/denied.",
    ),
    TestCase(
        id="SC-22", group=GROUP, control="MCP data egress", must_pass=True,
        preconditions=["An approved/allowlisted MCP server available"],
        method=["Connect the approved MCP server (${mcp_allowlisted}).",
                "Trace what repo data/context is sent externally."],
        commands=["# connect ${mcp_allowlisted}; capture the egress payload / context sent"],
        expected="Data egress matches expectation; sensitive/excluded content not transmitted.",
    ),
]

AGENT = Agent(
    key="group5",
    name="Group 5 - MCP",
    group=GROUP,
    description="MCP allowlist enforcement and MCP data-egress tracing.",
    test_cases=CASES,
)
