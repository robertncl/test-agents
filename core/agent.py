"""The Agent container.

Each module under ``agents/`` instantiates one ``Agent`` holding the TestCases
for a single plan-v0.1 group (G1..G6, FN, DP, DK). Agents are pure data +
selection helpers - they do not execute anything in this scaffold build.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import TestCase


@dataclass
class Agent:
    key: str              # short slug, e.g. "group2"
    name: str             # human name
    group: str            # group key (-> frameworks.GROUPS)
    description: str
    test_cases: list[TestCase] = field(default_factory=list)

    def get(self, test_id: str) -> TestCase | None:
        for tc in self.test_cases:
            if tc.id == test_id:
                return tc
        return None

    def select(
        self,
        ids: list[str] | None = None,
        must_pass_only: bool = False,
    ) -> list[TestCase]:
        out = []
        for tc in self.test_cases:
            if ids and tc.id not in ids:
                continue
            if must_pass_only and not tc.must_pass:
                continue
            out.append(tc)
        return out

    def must_pass_count(self) -> int:
        return sum(1 for tc in self.test_cases if tc.must_pass)
