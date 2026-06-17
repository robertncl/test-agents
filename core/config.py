"""POC configuration loader and evidence snapshots (plan v0.1).

Config is plain JSON (stdlib only) so the harness runs anywhere with python3 and
no `pip install`. Copy ``config/poc.example.json`` to ``config/poc.json`` and edit
it for your ring-fenced POC enterprise/org.
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
    """``${name}`` substitutions applied to method/command text at record build."""
    net = cfg.get("network", {})
    poc = cfg.get("poc", {})
    secrets = cfg.get("secrets", {}).get("honeytokens", {})
    docker = cfg.get("docker", {})
    mcp = cfg.get("mcp", {})
    excl = cfg.get("content_exclusion", {}).get("paths", [])
    return {
        "enterprise": str(poc.get("enterprise", "<poc-enterprise>")),
        "org": str(poc.get("org", "<poc-org>")),
        "mirror_host": str(net.get("mirror_host", "<mirror-host>")),
        "canary_endpoint": str(net.get("canary_endpoint", "<canary-endpoint>")),
        "image_mirror": str(docker.get("image_mirror", "<image-mirror>")),
        "run_flags": " ".join(docker.get("default_run_flags", [])),
        "mcp_allowlisted": str((mcp.get("allowlist") or ["<allowlisted-mcp>"])[0]),
        "mcp_nonallowlisted": str(mcp.get("nonallowlisted_test_server", "<nonallowlisted-mcp>")),
        "excluded_path": str(excl[0] if excl else "<excluded-path>"),
        "honeytoken_pat": str(secrets.get("github_pat", "<honeytoken-pat>")),
        "fake_api_key": str(secrets.get("fake_api_key", "<fake-api-key>")),
        "actions_secret": str(secrets.get("actions_secret", "<honeytoken-actions>")),
    }


def substitute(text: str, tok: dict[str, str]) -> str:
    for k, v in tok.items():
        text = text.replace("${" + k + "}", v)
    return text


def config_snapshot(cfg: dict) -> dict:
    """Redacted, evidence-relevant slice of config (Appendix B environment/config)."""
    return {
        "enterprise": cfg.get("poc", {}).get("enterprise"),
        "org": cfg.get("poc", {}).get("org"),
        "classification": cfg.get("poc", {}).get("classification"),
        "policies": cfg.get("policies", {}),
        "branch_protection": cfg.get("branch_protection", {}),
        "firewall": cfg.get("network", {}).get("firewall"),
        "network_allowlist": cfg.get("network", {}).get("allowlist"),
        "canary_endpoint": cfg.get("network", {}).get("canary_endpoint"),
        "mcp_allowlist": cfg.get("mcp", {}).get("allowlist"),
        "content_exclusion": cfg.get("content_exclusion", {}).get("paths"),
        "residency": cfg.get("residency", {}),
        "siem": cfg.get("siem", {}).get("platform"),
        "config_source": cfg.get("_source"),
    }


def env_snapshot(cfg: dict) -> dict:
    return {
        "framework": "copilot-app-poc-agents",
        "captured_at": _utc_now(),
        "host_platform": platform.platform(),
        "python": platform.python_version(),
        "dry_run": cfg.get("execution", {}).get("dry_run", True),
    }
