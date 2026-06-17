"""Policy model shared by every sandbox backend.

A :class:`Policy` is the single source of truth for what a sandboxed agent is
allowed to touch. Each backend translates the same policy object into its own
native enforcement primitives (docker flags, OpenShell policy file, Copilot
sandbox config), so a test written against the policy model runs unchanged
across all backends.

Policies are stored as JSON under ``policies/`` (stdlib only -- no PyYAML
dependency required to run the suite).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FilesystemPolicy:
    """Filesystem access rules.

    ``workspace`` is the one shared project directory that is bind-mounted into
    the sandbox; everything else on the host must be invisible. ``read_paths``
    / ``write_paths`` are additional explicit allowlists (used by backends that
    support fine-grained path policy). With ``default_deny`` set, anything not
    explicitly allowed is denied.
    """

    workspace: str = "/workspace"
    workspace_writable: bool = True
    read_paths: list[str] = field(default_factory=list)
    write_paths: list[str] = field(default_factory=list)
    default_deny: bool = True


@dataclass
class NetworkPolicy:
    """Egress network rules.

    ``default_deny`` with an empty ``allow_hosts`` means *no* network at all
    (full isolation). A non-empty ``allow_hosts`` is an egress allowlist and
    requires a backend that can do per-host filtering (see
    ``Backend.supports('network-allowlist')``).
    """

    default_deny: bool = True
    allow_hosts: list[str] = field(default_factory=list)
    allow_ports: list[int] = field(default_factory=lambda: [443])


@dataclass
class McpPolicy:
    """MCP (Model Context Protocol) access rules.

    ``servers`` is the full registry the user has configured (name -> spec).
    ``allow_servers`` is the subset the sandboxed agent may actually reach.
    With ``default_deny`` set, any server not in ``allow_servers`` is stripped
    from the agent's effective configuration and blocked at runtime.
    """

    default_deny: bool = True
    allow_servers: list[str] = field(default_factory=list)
    servers: dict[str, dict[str, Any]] = field(default_factory=dict)

    def effective_servers(self) -> dict[str, dict[str, Any]]:
        """Return only the MCP servers the agent is permitted to use.

        This is what a backend must actually render into the agent's MCP
        config. A denied server must never appear here.
        """
        if not self.default_deny:
            return dict(self.servers)
        return {
            name: spec
            for name, spec in self.servers.items()
            if name in self.allow_servers
        }

    def is_allowed(self, server_name: str) -> bool:
        if not self.default_deny:
            return True
        return server_name in self.allow_servers


@dataclass
class Policy:
    name: str
    description: str = ""
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    mcp: McpPolicy = field(default_factory=McpPolicy)

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        return cls(
            name=d["name"],
            description=d.get("description", ""),
            filesystem=FilesystemPolicy(**d.get("filesystem", {})),
            network=NetworkPolicy(**d.get("network", {})),
            mcp=McpPolicy(**d.get("mcp", {})),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        path = Path(path)
        return cls.from_dict(json.loads(path.read_text()))

    @classmethod
    def load(cls, name_or_path: str | Path) -> "Policy":
        """Load by policy name (resolved against ``policies/``) or by path."""
        p = Path(name_or_path)
        if p.exists():
            return cls.from_file(p)
        candidate = POLICIES_DIR / f"{name_or_path}.json"
        if candidate.exists():
            return cls.from_file(candidate)
        raise FileNotFoundError(
            f"No policy named {name_or_path!r} (looked in {POLICIES_DIR})"
        )


REPO_ROOT = Path(__file__).resolve().parent.parent
POLICIES_DIR = REPO_ROOT / "policies"


def native_policy_path(backend: str, policy_name: str, ext: str) -> Path:
    """Path to a sandbox-native policy artifact.

    Native policies live under ``policies/<backend>/<name>.<ext>`` and are
    authored in each sandbox's own format (Docker primitives, OpenShell policy
    schema, bubblewrap args, Seatbelt profile). ``{workspace}`` placeholders in
    them are substituted with the host workspace dir at runtime.
    """
    return POLICIES_DIR / backend / f"{policy_name}.{ext}"
