"""Functional / value scenarios (FN-01..04). B.8. Value measures, not must-pass."""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

GROUP = "FN"

CASES = [
    TestCase(
        id="FN-01", group=GROUP, control="Prompt -> plan -> draft PR on a backlog issue",
        measure="Time-to-PR; reviewer edits required; correctness.",
        method=["Take a backlog issue from prompt to plan to a draft PR."],
        commands=["# assign a seeded backlog issue to the agent; measure to draft PR"],
        expected="A correct, reviewable draft PR is produced; reviewer edits within target.",
    ),
    TestCase(
        id="FN-02", group=GROUP, control="Parallel agents via My Work",
        measure="Throughput; collision/regression incidents.",
        method=["Run bug fix + feature + review-feedback simultaneously via My Work."],
        commands=["# launch 3 parallel sessions from My Work; track throughput + collisions"],
        expected="Sessions progress independently; no collisions/regressions beyond target.",
    ),
    TestCase(
        id="FN-03", group=GROUP, control="Copilot code review on real-style PRs",
        measure="Useful-finding rate; reviewer time saved.",
        method=["Run Copilot code review on real-style PRs (medium vs low tier)."],
        commands=["# open seeded-defect PRs; run Copilot review; score useful findings"],
        expected="Actionable findings on >=80% of seeded-defect PRs (B.2).",
    ),
    TestCase(
        id="FN-04", group=GROUP, control="Canvas-based steering mid-task",
        measure="Steering success; rework.",
        method=["Redirect an agent mid-task from a Canvas surface."],
        commands=["# start a task; mid-run, redirect via Canvas; measure steering success"],
        expected="Agent accepts redirection; rework within target.",
    ),
]

AGENT = Agent(
    key="functional",
    name="Functional / Value Scenarios",
    group=GROUP,
    description="Prompt-to-PR, parallel agents via My Work, Copilot code review value, "
                "and Canvas-based steering.",
    test_cases=CASES,
)
