"""Test-agent package for the GitHub Copilot App POC security verification plan.

Each agent corresponds to a test case ID (SC-* / FN-* / DP-*) from the POC plan
(``GitHub-Copilot-App-POC-Security-Verification-Plan.md``, section B.7).

Importing :mod:`agents` registers every shipped agent via its sub-packages so the
CLI in ``run.py`` can discover them through :func:`agents.base.all_agents`.
"""

from . import base  # noqa: F401  (re-export core types)

# Import group sub-packages for their import side effect: each module decorates
# its agent class with ``@base.register``, populating the global registry.
from . import group2  # noqa: F401,E402

__all__ = ["base", "group2"]
