"""Test agents, one per plan-v0.1 group (GitHub Copilot App POC).

Importing this package exposes:
- ``ALL_AGENTS``  - ordered list of every Agent (Group 2 first, per setup priority)
- ``get_agent``   - look up an agent by key
- ``find_case``   - locate (agent, testcase) by test id across all agents
"""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

from .data_protection import AGENT as DATA
from .docker_baseline import AGENT as DOCKER
from .functional import AGENT as FUNCTIONAL
from .group1_identity import AGENT as GROUP1
from .group2_containment import AGENT as GROUP2
from .group3_code_assurance import AGENT as GROUP3
from .group4_ai_threats import AGENT as GROUP4
from .group5_mcp import AGENT as GROUP5
from .group6_audit import AGENT as GROUP6

# Group 2 (containment) + its Docker baseline first - set up first per request.
ALL_AGENTS: list[Agent] = [
    GROUP2,
    DOCKER,
    GROUP1,
    GROUP3,
    GROUP4,
    GROUP5,
    GROUP6,
    FUNCTIONAL,
    DATA,
]


def get_agent(key: str) -> Agent | None:
    for a in ALL_AGENTS:
        if a.key == key:
            return a
    return None


def find_case(test_id: str) -> tuple[Agent, TestCase] | None:
    for a in ALL_AGENTS:
        tc = a.get(test_id)
        if tc:
            return a, tc
    return None
