"""Run the GitHub Copilot agent inside a sandbox backend.

The security scenarios deliberately use small deterministic shell probes rather
than the live agent, so the suite is reproducible and runs without Copilot
credentials. This module is the bridge for when you *do* want the real agent in
the loop: it launches the Copilot CLI as the in-sandbox command, so the agent
itself is confined by exactly the same policy the probes validate.

The CLI invocation is centralised and overridable -- adapt to the Copilot CLI
version you have, or set the env var:

    COPILOT_AGENT_CMD   template; {prompt} is replaced with the (shell-quoted)
                        task prompt. Default assumes a non-interactive agent
                        invocation:  copilot -p {prompt} --allow-all-tools

Example
-------
    from sandbox.backends import DockerBackend
    from sandbox.policy import Policy
    from sandbox.agent import run_copilot_agent

    res = run_copilot_agent(
        DockerBackend(),
        prompt="Read README.md and summarise it.",
        policy=Policy.load("workspace-rw"),
        workspace=Path("./my-project"),
    )
    print(res.stdout)
"""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path

from .backends.base import Backend, RunResult
from .policy import Policy

DEFAULT_AGENT_CMD = os.environ.get(
    "COPILOT_AGENT_CMD", "copilot -p {prompt} --allow-all-tools"
)
COPILOT_BIN = os.environ.get("COPILOT_BIN", "copilot")


def render_mcp_config(policy: Policy) -> dict:
    """Render the Copilot agent's native MCP config honoring the policy.

    The MCP config format belongs to the agent (Copilot), not the sandbox, so
    it is shared across backends. Only allowlisted servers appear, regardless of
    what the user configured -- this is the artifact the agent actually loads.
    """
    return {"mcpServers": policy.mcp.effective_servers()}


def copilot_available() -> tuple[bool, str]:
    """Whether the Copilot CLI looks installed (auth is checked at run time)."""
    if "{prompt}" not in DEFAULT_AGENT_CMD:
        return False, "COPILOT_AGENT_CMD must contain a {prompt} placeholder"
    binary = shlex.split(DEFAULT_AGENT_CMD)[0]
    if shutil.which(binary) is None:
        return False, f"Copilot CLI {binary!r} not found on PATH"
    return True, f"copilot CLI: {binary}"


def build_agent_argv(prompt: str) -> list[str]:
    cmd = DEFAULT_AGENT_CMD.format(prompt=shlex.quote(prompt))
    return ["/bin/sh", "-lc", cmd]


def run_copilot_agent(
    backend: Backend,
    *,
    prompt: str,
    policy: Policy,
    workspace: Path,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Launch the Copilot agent inside ``backend`` confined by ``policy``.

    The agent process is the sandboxed command, so every file/network/MCP action
    it takes is subject to the same enforcement the probes assert.
    """
    agent_env = dict(env or {})
    # forward a token if present so the agent can authenticate inside the sandbox
    for var in ("GITHUB_TOKEN", "GH_TOKEN", "COPILOT_API_KEY"):
        if var in os.environ and var not in agent_env:
            agent_env[var] = os.environ[var]
    return backend.run(
        build_agent_argv(prompt),
        policy=policy,
        workspace=workspace,
        timeout=timeout,
        env=agent_env,
    )
