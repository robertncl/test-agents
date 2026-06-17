"""Docker sandbox -- MCP access policy."""

import pytest

from sandbox.scenarios import scenarios_for
from sandbox.testing import check

BACKEND = "docker"
SCENARIOS = scenarios_for("mcp-policy")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.key for s in SCENARIOS])
def test_mcp_policy(scenario):
    check(scenario, BACKEND)
