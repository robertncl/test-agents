"""POC configuration loader and evidence snapshots.

Config is plain JSON (stdlib only, no third-party deps) so the harness runs
anywhere with ``python3`` and no ``pip install``. Edit ``config/poc.json`` (copy
of ``config/poc.example.json``) to point the agents at your ring-fenced POC org.
"""

from __future__ import annotations

import datetime
import json
import os
import platform

DEFAULT_CONFIG_PATHS = ["config/poc.json", "config/poc.example.json"]


def load_config(path: str | None = None) -> dict:
    paths = [path] if path else DEFAULT_CONFIG_PATHS
    for p in paths:
        if p and os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                cfg = json.load(f)
            cfg["_source"] = p
            return cfg
    raise FileNotFoundError(
        f"No POC config found. Looked in: {paths}. "
        "Copy config/poc.example.json to config/poc.json and edit it."
    )


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def tokens(cfg: dict) -> dict[str, str]:
    """Placeholder substitutions applied to method/command text at record build.

    Test cases use ``${name}`` tokens so the same case definition adapts to any
    POC environment without editing code.
    """
    net = cfg.get("network", {})
    poc = cfg.get("poc", {})
    secrets = cfg.get("secrets", {}).get("honeytokens", {})
    docker = cfg.get("docker", {})
    return {
        "org": str(poc.get("org", "<poc-org>")),
        "mirror_host": str(net.get("mirror_host", "<mirror-host>")),
        "canary_endpoint": str(net.get("canary_endpoint", "<canary-endpoint>")),
        "image_mirror": str(docker.get("image_mirror", "<image-mirror>")),
        "run_flags": " ".join(docker.get("default_run_flags", [])),
        "honeytoken_pat": str(secrets.get("github_pat", "<honeytoken-pat>")),
        "actions_secret": str(secrets.get("actions_secret", "<honeytoken-actions>")),
        "copilot_env_secret": str(secrets.get("copilot_env_secret", "<honeytoken-copilot-env>")),
    }


def substitute(text: str, tok: dict[str, str]) -> str:
    for k, v in tok.items():
        text = text.replace("${" + k + "}", v)
    return text


def config_snapshot(cfg: dict) -> dict:
    """Redacted, evidence-relevant slice of config (Appendix B: config snapshot)."""
    policies = cfg.get("policies", {})
    net = cfg.get("network", {})
    return {
        "org": cfg.get("poc", {}).get("org"),
        "classification": cfg.get("poc", {}).get("classification"),
        "policies": policies,
        "network_allowlist": net.get("allowlist"),
        "canary_endpoint": net.get("canary_endpoint"),
        "mirror_host": net.get("mirror_host"),
        "siem": cfg.get("siem", {}).get("platform"),
        "config_source": cfg.get("_source"),
    }


def env_snapshot(cfg: dict) -> dict:
    """Environment snapshot for evidence (Appendix B: environment snapshot)."""
    return {
        "framework": "copilot-sandbox-poc-agents",
        "captured_at": _utc_now(),
        "host_platform": platform.platform(),
        "python": platform.python_version(),
        "dry_run": cfg.get("execution", {}).get("dry_run", True),
    }
