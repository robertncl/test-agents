"""Test agents, one per sandbox surface in the POC plan.

Importing this package exposes:
- ``ALL_AGENTS``   - ordered list of every Agent
- ``find_case``    - locate (agent, testcase) by test id across all agents
"""

from __future__ import annotations

from core.agent import Agent
from core.model import TestCase

from .adversarial_agent import AGENT as ADVERSARIAL
from .audit_agent import AGENT as AUDIT
from .cloud_sandbox_agent import AGENT as CLOUD
from .copilot_app_agent import AGENT as APP
from .docker_sandbox_agent import AGENT as DOCKER
from .governance_agent import AGENT as GOVERNANCE
from .guardrail_agent import AGENT as GUARDRAIL
from .local_sandbox_agent import AGENT as LOCAL

ALL_AGENTS: list[Agent] = [
    DOCKER,
    LOCAL,
    CLOUD,
    APP,
    GOVERNANCE,
    GUARDRAIL,
    ADVERSARIAL,
    AUDIT,
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
