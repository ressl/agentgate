"""Configuration loading and defaults."""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import GatewayConfig

DEFAULT_CONFIG_NAME = "mcp-firewall.yaml"


def load_config(path: str | Path | None = None) -> GatewayConfig:
    """Load configuration from YAML file or return defaults."""
    if path is None:
        path = Path.cwd() / DEFAULT_CONFIG_NAME

    path = Path(path)
    if not path.exists():
        return GatewayConfig()

    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    # Map YAML keys to model fields
    mapped: dict = {}
    mapped["version"] = raw.get("version", 1)
    mapped["default_action"] = raw.get("defaultAction", raw.get("default_action", "prompt"))

    if "killSwitch" in raw or "kill_switch" in raw:
        ks = raw.get("killSwitch", raw.get("kill_switch", {}))
        mapped["kill_switch"] = ks

    if "globalRateLimit" in raw or "rate_limit" in raw:
        rl = raw.get("globalRateLimit", raw.get("rate_limit", {}))
        mapped["rate_limit"] = {
            "max_calls": rl.get("maxCalls", rl.get("max_calls", 200)),
            "window_seconds": rl.get("windowSeconds", rl.get("window_seconds", 60)),
            "enabled": rl.get("enabled", True),
        }

    if "security" in raw:
        sec = raw["security"]
        if "injectionDetection" in sec:
            mapped["injection"] = sec["injectionDetection"]
        if "egressControl" in sec:
            mapped["egress"] = sec["egressControl"]

    if "injection" in raw:
        mapped["injection"] = raw["injection"]
    if "egress" in raw:
        mapped["egress"] = raw["egress"]
    if "secrets" in raw:
        mapped["secrets"] = raw["secrets"]
    if "pii" in raw:
        mapped["pii"] = raw["pii"]

    if "responseScanning" in raw:
        rs = raw["responseScanning"]
        if "detectSecrets" in rs:
            mapped.setdefault("secrets", {})["enabled"] = rs["detectSecrets"]
        if "detectPII" in rs:
            mapped.setdefault("pii", {})["enabled"] = rs["detectPII"]

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
