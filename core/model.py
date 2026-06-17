"""Value objects shared by every test agent (GitHub Copilot App POC, plan v0.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Disposition(str, Enum):
    """Outcome of a test case.

    Appendix B template records Status as Pass/Fail/Blocked; PARTIAL captures
    'GO WITH CONDITIONS' (passed only with a documented compensating control),
    and NOT_RUN is the default for a freshly scaffolded record.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_RUN = "NOT_RUN"


# Dispositions that count as "executed" for coverage maths.
RUN_DISPOSITIONS = {
    Disposition.PASS,
    Disposition.FAIL,
    Disposition.BLOCKED,
    Disposition.PARTIAL,
}
# Dispositions that block a GO for a must-pass case.
BLOCKING_DISPOSITIONS = {Disposition.FAIL, Disposition.BLOCKED}


@dataclass
class TestCase:
    """A single POC test case (B.7 SC-*, B.8 FN-*, B.9 DP-*, Docker DK-*).

    Field names mirror the Appendix B test-case template:
    control-under-test, preconditions, steps (method), expected (pass) result.
    ``must_pass`` marks the bypass-critical cases (the gate per B.2 / B.12).
    ``live_action`` is an unused hook for a future self-executing case.
    """

    id: str
    group: str                         # group key (see frameworks.GROUPS)
    control: str                       # control under test
    expected: str                      # expected (pass) result
    method: list[str] = field(default_factory=list)        # steps
    preconditions: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)      # concrete commands/prompts
    must_pass: bool = False            # bypass-critical (B.7 "Must-pass")
    negative: bool = False             # a bypass attempt that must be blocked AND logged
    measure: str = ""                  # functional cases (B.8 measure)
    notes: str = ""
    live_action: Optional[Callable] = None
