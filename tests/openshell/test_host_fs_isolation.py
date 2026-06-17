"""OpenShell (NVIDIA) sandbox -- host filesystem isolation."""

import pytest

from sandbox.scenarios import scenarios_for
from sandbox.testing import check

BACKEND = "openshell"
SCENARIOS = scenarios_for("host-fs-isolation")


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.key for s in SCENARIOS])
def test_host_fs_isolation(scenario):
    check(scenario, BACKEND)
