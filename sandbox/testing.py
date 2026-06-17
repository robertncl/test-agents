"""Pytest glue shared by the per-sandbox test folders.

Each ``tests/<backend>/`` folder pins ``BACKEND`` to one sandbox and calls
:func:`check`, so the same scenarios run independently per sandbox while the
security logic stays defined once in :mod:`sandbox.scenarios`.
"""

from __future__ import annotations

import pytest

from .backends import get_backend
from .scenarios import PASS, SKIP, Scenario


def check(scenario: Scenario, backend_name: str) -> None:
    """Evaluate ``scenario`` on ``backend_name`` and map the outcome to pytest.

    SKIP (backend unavailable or capability not enforced) becomes a pytest skip;
    anything other than PASS becomes a failure with the diagnostic message.
    """
    outcome = scenario.evaluate(get_backend(backend_name))
    if outcome.status == SKIP:
        pytest.skip(outcome.message)
    assert outcome.status == PASS, (
        f"[{backend_name}] {scenario.title}: {outcome.message}\n{outcome.evidence}"
    )
