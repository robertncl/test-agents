"""Sandbox agent security-control test harness.

This package provides a backend-agnostic way to launch the GitHub Copilot
agent (or an arbitrary probe command) inside a sandbox and assert that the
sandbox enforces three classes of security control:

  * host filesystem isolation          (tests/test_host_fs_isolation.py)
  * filesystem + network access policy (tests/test_fs_policy.py, test_network_policy.py)
  * MCP access policy                  (tests/test_mcp_policy.py)

Three sandbox backends are supported behind a common interface:

  * docker         -- a plain Docker container (fully runnable reference impl)
  * openshell      -- NVIDIA OpenShell runtime  (adapter; verify CLI flags)
  * copilot_local  -- GitHub Copilot CLI local sandbox (adapter; verify CLI flags)

The security logic lives once in ``sandbox.scenarios`` and is consumed both by
the pytest suite under ``tests/`` and by the zero-dependency ``run_tests.py``.
"""

from .policy import Policy

__all__ = ["Policy"]
