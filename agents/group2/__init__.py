"""Group 2 — Containment, isolation & egress (POC plan section B.7).

Importing this package registers SC-07 … SC-12 with the agent registry.
"""

from . import (  # noqa: F401  (import for registration side effects)
    sc07_local_sandbox_isolation,
    sc08_local_sandbox_central_enforcement,
    sc09_worktree_session_isolation,
    sc10_cloud_sandbox_ephemerality,
    sc11_agent_firewall_egress,
    sc12_agent_firewall_change_control,
)
