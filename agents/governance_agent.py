"""Enterprise governance & policy enforcement agent.

Covers POC plan s.6.2: TC-S-08..13. Verifies that org-level gating, Intune/MDM
local policy, the agent firewall, and policy inheritance are provably enforced
and NOT overridable by the developer.
"""

from __future__ import annotations

from core.agent import Agent
from core.model import Priority as P
from core.model import TestCase

CASES = [
    TestCase(
        id="TC-S-08",
        priority=P.P1,
        title="Org gate for cloud sandbox",
        control="Members cannot self-enable cloud sandbox when org policy is off",
        theme="governance",
        criterion="C2",
        method=[
            "With 'Cloud Sandbox access' DISABLED at org/enterprise level,",
            "attempt `copilot --cloud` as an ordinary member.",
        ],
        commands=["copilot --cloud   # expect: unavailable / denied"],
        pass_criteria="Cloud sandbox is unavailable; the member cannot self-enable it.",
    ),
    TestCase(
        id="TC-S-09",
        priority=P.P1,
        title="Intune/MDM local policy push",
        control="MDM-pushed local-sandbox policy is enforced and non-overridable",
        theme="governance",
        criterion="C2",
        method=[
            "Push a restrictive local-sandbox policy via Microsoft Intune.",
            "On the endpoint, attempt to override/relax it locally.",
        ],
        commands=["# Intune: assign restrictive local-sandbox profile", "# endpoint: attempt local override"],
        pass_criteria="Policy is enforced on the endpoint; the developer cannot override it.",
    ),
    TestCase(
        id="TC-S-10",
        priority=P.P1,
        title="Firewall default-on (cloud)",
        control="Default egress firewall blocks the canary and warns on the PR",
        theme="governance",
        criterion="C2",
        method=[
            "With default firewall, have the cloud agent attempt egress to ${canary_endpoint}.",
        ],
        commands=["# agent (Bash tool) attempts: curl ${canary_endpoint}"],
        pass_criteria=(
            "Egress is blocked; a warning is surfaced on the PR naming the blocked "
            "address + command."
        ),
    ),
    TestCase(
        id="TC-S-11",
        priority=P.P1,
        title="Org-locked firewall",
        control="A repo cannot weaken an org-enforced firewall setting",
        theme="governance",
        criterion="C2",
        method=[
            "Set org firewall to Enabled (NOT 'let repositories decide').",
            "At repo level, attempt to disable/weaken it.",
        ],
        commands=["# org: firewall = Enabled (locked)", "# repo: attempt to disable -> expect blocked"],
        pass_criteria="The repo cannot weaken the org setting.",
    ),
    TestCase(
        id="TC-S-12",
        priority=P.P1,
        title="Custom allowlist scoping",
        control="Only the allowlisted domain/subdomain/path is reachable",
        theme="governance",
        criterion="C2",
        method=[
            "Add ${mirror_host} to the custom allowlist.",
            "Verify subdomain/path scoping vs a sibling host that is NOT allowlisted.",
        ],
        commands=[
            "# agent attempts: reach ${mirror_host} (allow) and a sibling host (deny)",
        ],
        pass_criteria=(
            "Only the allowlisted domain/subdomains (or URL path) are reachable; "
            "sibling hosts are blocked."
        ),
    ),
    TestCase(
        id="TC-S-13",
        priority=P.P2,
        title="Policy inheritance to sandbox",
        control="Cloud-agent policies apply to cloud sandbox sessions",
        theme="governance",
        criterion="C2",
        method=["Confirm the org's cloud-agent controls apply to cloud sandbox sessions with no extra setup."],
        commands=["# launch a cloud sandbox session; verify firewall/guardrail policy is in force"],
        pass_criteria="Sandbox session inherits the org's cloud-agent controls with no extra setup.",
    ),
]

AGENT = Agent(
    key="governance",
    name="Governance & Policy Agent",
    surface="Enterprise governance & policy enforcement",
    description=(
        "Org gating, Intune/MDM local policy, agent firewall (default-on, org-lock, "
        "allowlist scoping), and policy inheritance to sandbox sessions."
    ),
    test_cases=CASES,
)
