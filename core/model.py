"""Value objects shared by every test agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Priority(str, Enum):
    """POC plan priority: P1 = gate-blocking, P2 = important, P3 = nice-to-have."""

    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Disposition(str, Enum):
    """Outcome of a test case (Appendix B requires a pass/fail disposition)."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"          # passed with a documented gap / compensating control
    SKIPPED = "SKIPPED"          # not applicable on this surface/run
    BLOCKED = "BLOCKED"          # could not execute (env/preview unavailable)
    MANUAL_REVIEW = "MANUAL_REVIEW"  # evidence captured, awaiting human disposition
    NOT_RUN = "NOT_RUN"          # default for a freshly scaffolded record


# Convenience for callers that want the set of failing-ish states.
NEGATIVE_DISPOSITIONS = {Disposition.FAIL, Disposition.BLOCKED}
RUN_DISPOSITIONS = {
    Disposition.PASS,
    Disposition.FAIL,
    Disposition.PARTIAL,
    Disposition.MANUAL_REVIEW,
}


@dataclass
class TestCase:
    """A single POC test case, encoded as data.

    ``live_action`` is an optional hook ``(RunContext) -> Disposition`` for teams
    that later want a case to execute itself. It is ``None`` for every case in
    this scaffold build - execution is manual and recorded via ``run.py record``.
    """

    id: str
    priority: Priority
    title: str
    control: str                      # control under test / objective
    pass_criteria: str
    method: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)  # concrete commands/prompts
    theme: str = ""                   # regulatory theme key (see frameworks.THEMES)
    criterion: str = ""               # go/no-go criterion key (see frameworks.CRITERIA)
    threat: str = ""                  # research-derived threat (adversarial cases)
    notes: str = ""
    live_action: Optional[Callable] = None

    def is_gate_blocking(self) -> bool:
        return self.priority == Priority.P1
