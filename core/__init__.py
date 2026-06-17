"""Core framework for the GitHub Copilot / Docker sandbox POC test agents.

This package provides the shared model used by every test agent:

- ``model``      - TestCase, Priority, Disposition value objects
- ``frameworks`` - regulatory theme + go/no-go criterion mappings (POC plan s.7 / s.9)
- ``config``     - POC configuration loader + evidence snapshots
- ``evidence``   - Appendix B evidence record (build / load / save)
- ``agent``      - the Agent container each domain module instantiates
- ``report``     - traceability matrix, go/no-go scorecard, run summary

Nothing here executes against a live environment. Test cases are *scaffolds*:
the concrete commands / prompts / pass-criteria are encoded as data so a POC
engineer can run them by hand (or wire a live hook) and record evidence.
"""

__version__ = "1.0.0"
