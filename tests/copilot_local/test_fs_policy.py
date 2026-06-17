"""GitHub Copilot local sandbox -- filesystem access policy."""

import pytest

from sandbox.scenarios import scenarios_for
from sandbox.testing import check

BACKEND = "copilot_local"
SCENARIOS = scenarios_for("fs-policy")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.key for s in SCENARIOS])
def test_fs_policy(scenario):
    check(scenario, BACKEND)
