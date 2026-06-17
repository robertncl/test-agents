"""OpenShell (NVIDIA) sandbox -- network access policy (incl. egress allowlist)."""

import pytest

from sandbox.scenarios import scenarios_for
from sandbox.testing import check

BACKEND = "openshell"
SCENARIOS = scenarios_for("network-policy")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.key for s in SCENARIOS])
def test_network_policy(scenario):
    check(scenario, BACKEND)
