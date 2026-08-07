"""Configuration loading and defaults."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import GatewayConfig

DEFAULT_CONFIG_NAME = "mcp-firewall.yaml"

# Documented camelCase YAML keys -> snake_case model fields.
_CAMEL_TO_SNAKE = {
    "filePath": "file_path",
    "blockPrivateIPs": "block_private_ips",
    "blockCloudMetadata": "block_cloud_metadata",
    "minSeverity": "min_severity",
    "webhookUrl": "webhook_url",
    "feedDir": "feed_dir",
}


def _map_section(value: Any) -> dict:
    """Coerce a config section to a dict and map camelCase keys to snake_case.

    Non-dict values (e.g. ``secrets: false``) are treated as an enabled flag.
    """
    if not isinstance(value, dict):
        return {"enabled": bool(value)}
    return {_CAMEL_TO_SNAKE.get(key, key): item for key, item in value.items()}


def load_config(path: str | Path | None = None) -> GatewayConfig:
    """Load configuration from YAML file or return defaults.

    When ``path`` is None, the default config file in the CWD is used if it
    exists, otherwise defaults are returned. An explicitly given path that
    does not exist raises ``FileNotFoundError`` — silently falling back to
    defaults would run the firewall with a policy the caller never intended.
    """
    if path is None:
        path = Path.cwd() / DEFAULT_CONFIG_NAME
        if not path.exists():
            return GatewayConfig()

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    # Map YAML keys to model fields
    mapped: dict = {}
    mapped["version"] = raw.get("version", 1)
    mapped["default_action"] = raw.get("defaultAction", raw.get("default_action", "prompt"))

    if "killSwitch" in raw or "kill_switch" in raw:
        ks = raw.get("killSwitch", raw.get("kill_switch", {}))
        mapped["kill_switch"] = _map_section(ks)

    if "globalRateLimit" in raw or "rate_limit" in raw:
        rl = raw.get("globalRateLimit", raw.get("rate_limit", {}))
        mapped["rate_limit"] = {
            "max_calls": rl.get("maxCalls", rl.get("max_calls", 200)),
            "window_seconds": rl.get("windowSeconds", rl.get("window_seconds", 60)),
            "enabled": rl.get("enabled", True),
        }

    if "security" in raw:
        sec = raw["security"]
        if isinstance(sec, dict):
            if "injectionDetection" in sec:
                mapped["injection"] = _map_section(sec["injectionDetection"])
            if "egressControl" in sec:
                mapped["egress"] = _map_section(sec["egressControl"])

    if "injection" in raw:
        mapped["injection"] = _map_section(raw["injection"])
    if "egress" in raw:
        mapped["egress"] = _map_section(raw["egress"])
    if "secrets" in raw:
        mapped["secrets"] = _map_section(raw["secrets"])
    if "pii" in raw:
        mapped["pii"] = _map_section(raw["pii"])

    if "responseScanning" in raw:
        rs = raw["responseScanning"]
        if isinstance(rs, dict):
            # Explicit secrets:/pii: sections take precedence over responseScanning.
            if "detectSecrets" in rs and "secrets" not in mapped:
                mapped["secrets"] = {"enabled": bool(rs["detectSecrets"])}
            if "detectPII" in rs and "pii" not in mapped:
                mapped["pii"] = {"enabled": bool(rs["detectPII"])}

    if "alerts" in raw:
        alerts = _map_section(raw["alerts"])
        # Channel subsections may use camelCase keys too (e.g. webhookUrl)
        for channel in ("slack", "webhook", "syslog"):
            if channel in alerts:
                alerts[channel] = _map_section(alerts[channel])
        mapped["alerts"] = alerts

    if "threatFeed" in raw or "threat_feed" in raw:
        tf = raw.get("threatFeed", raw.get("threat_feed", {}))
        mapped["threat_feed"] = _map_section(tf)

    mapped["agents"] = raw.get("agents", {})
    mapped["rules"] = raw.get("rules", [])
    mapped["audit"] = raw.get("audit", {})

    return GatewayConfig(**mapped)


def generate_default_config() -> str:
    """Generate a starter mcp-firewall.yaml."""
    return """# mcp-firewall configuration
# Docs: https://github.com/ressl/mcp-firewall/blob/main/docs/policies.md
version: 1
defaultAction: prompt  # allow | deny | prompt

globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

security:
  injectionDetection:
    enabled: true
    sensitivity: medium  # low | medium | high
  egressControl:
    enabled: true
    blockPrivateIPs: true
    blockCloudMetadata: true

responseScanning:
  detectSecrets: true
  detectPII: false

# Threat feed: built-in community detection rules for known attack patterns
# threatFeed:
#   enabled: true
#   feedDir: ./my-rules  # additional custom rules directory

# Alerts: notify on denied tool calls (slack, generic webhook, or syslog/CEF)
# alerts:
#   enabled: true
#   minSeverity: high  # critical | high | medium | low | info
#   slack:
#     webhookUrl: https://hooks.slack.com/services/...
#   webhook:
#     url: https://siem.example.com/alerts
#   syslog:
#     host: localhost
#     port: 514

# Agent-specific policies (RBAC)
# agents:
#   claude-desktop:
#     allow: [read_file, search]
#     deny: [exec, shell, rm]
#     rate_limit: "100/min"
#   cursor:
#     allow: [read_file, write_file]
#     require_approval: [exec]

rules:
  # Block credential access
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
    message: "SSH key access blocked"

  # Block env files
  - name: block-env-files
    tool: "*"
    match:
      arguments:
        path: "**/.env*"
    action: deny
    message: "Environment file access blocked"

  # Block credential directories
  - name: block-credentials
    tool: "*"
    match:
      arguments:
        path: "**/.aws/**"
    action: deny

  # Approve shell commands
  - name: approve-shell
    tool: "shell_exec|run_command|execute_command|bash"
    action: prompt

  # Allow safe reads
  - name: allow-reads
    tool: "read_file|get_file_contents|view_file|list_directory"
    action: allow

audit:
  enabled: true
  path: mcp-firewall.audit.jsonl
"""
