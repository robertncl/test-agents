"""The Agent container.

Each domain module under ``agents/`` instantiates one ``Agent`` holding the
TestCases for a single sandbox surface (Docker, Copilot local, Copilot cloud,
Copilot app, governance, guardrails, adversarial, audit). Agents are pure data
+ selection helpers - they do not execute anything in this scaffold build.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Priority, TestCase


@dataclass
class Agent:
    key: str              # short slug, e.g. "docker"
    name: str             # human name
    surface: str          # the sandbox surface under test (recorded in evidence)
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
        priorities: list[str] | None = None,
    ) -> list[TestCase]:
        out = []
        for tc in self.test_cases:
            if ids and tc.id not in ids:
                continue
            if priorities and tc.priority.value not in priorities:
                continue
            out.append(tc)
        return out

    def counts_by_priority(self) -> dict[str, int]:
        counts = {p.value: 0 for p in Priority}
        for tc in self.test_cases:
            counts[tc.priority.value] += 1
        return counts
