"""mcp-firewall SDK — Use the security pipeline from any Python application.

This module provides a simple API for integrating mcp-firewall's security
pipeline into any AI agent framework, not just MCP.

Usage:
    from mcp_firewall.sdk import Gateway

    gw = Gateway()                           # Load mcp-firewall.yaml or defaults
    gw = Gateway(config_path="my-policy.yaml")  # Custom config

    # Check before executing a tool
    decision = gw.check("exec", {"command": "rm -rf /"}, agent="claude")
    if decision.blocked:
        print(f"Blocked: {decision.reason}")
    else:
        # Safe to execute
        result = execute_tool(...)

        # Scan the result
        cleaned, findings = gw.scan_response(result)

Example with OpenClaw-style tools:
    gw = Gateway()

    # Before exec
    d = gw.check("exec", {"command": "ls -la /tmp"}, agent="openclaw")
    if not d.blocked:
        run_command("ls -la /tmp")

    # Before read
    d = gw.check("read", {"path": "/etc/passwd"}, agent="openclaw")
    # → Blocked by egress/policy rules

    # Before web_fetch
    d = gw.check("web_fetch", {"url": "http://169.254.169.254/meta"}, agent="openclaw")
    # → Blocked: Cloud metadata SSRF
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import load_config
from .models import Action, GatewayConfig, ToolCallRequest, ToolCallResponse
from .pipeline.runner import PipelineRunner


@dataclass
class CheckResult:
    """Result of a security check."""

    blocked: bool
    action: str  # allow, deny, prompt, redact
    reason: str
    severity: str
    stage: str | None

    @property
    def allowed(self) -> bool:
        return not self.blocked


@dataclass
class ScanResult:
    """Result of a response scan."""

    content: str
    modified: bool
    findings: list[dict[str, str]]


class Gateway:
    """mcp-firewall SDK — security pipeline for any AI agent framework.

    Works with OpenClaw, LangChain, CrewAI, AutoGen, or any custom agent.
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        config: GatewayConfig | None = None,
        auto_approve: bool = True,  # SDK mode: no interactive prompts
    ) -> None:
        if config:
            self._config = config
        else:
            self._config = load_config(config_path)

        # Disable audit in SDK mode by default (caller handles logging)
        if config is None:
            self._config.audit.enabled = False

        self._pipeline = PipelineRunner(self._config, auto_approve=auto_approve)

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        agent: str = "default",
    ) -> CheckResult:
        """Check if a tool call should be allowed.

        Args:
            tool_name: Name of the tool (e.g., "exec", "read", "web_fetch")
            arguments: Tool arguments to check
            agent: Agent identifier for RBAC

        Returns:
            CheckResult with blocked/allowed status and reason
        """
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments or {},
            agent_id=agent,
        )

        decision = self._pipeline.evaluate_inbound(request)

        if decision is None:
            return CheckResult(
                blocked=False,
                action="allow",
                reason="",
                severity="info",
                stage=None,
            )

        return CheckResult(
            blocked=decision.action in (Action.DENY,),
            action=decision.action.value,
            reason=decision.reason,
            severity=decision.severity.value,
            stage=decision.stage.value if decision.stage else None,
        )

    def scan_response(
        self,
        content: str,
        tool_name: str = "",
        agent: str = "default",
    ) -> ScanResult:
        """Scan a tool response for secrets, PII, and other sensitive data.

        Args:
            content: The tool output text to scan
            tool_name: Name of the tool that produced this output
            agent: Agent identifier

        Returns:
            ScanResult with cleaned content and findings
        """
        request = ToolCallRequest(tool_name=tool_name, agent_id=agent)
        response = ToolCallResponse(
            request_id=request.id,
            content=[{"type": "text", "text": content}],
        )

        scanned_response, decisions = self._pipeline.scan_outbound(request, response)

        modified = any(d.action == Action.REDACT for d in decisions)
        cleaned_text = scanned_response.content[0].get("text", content) if scanned_response.content else content

        findings = [
            {
                "stage": d.stage.value if d.stage else "unknown",
                "severity": d.severity.value,
                "reason": d.reason,
                "action": d.action.value,
            }
            for d in decisions
        ]

        return ScanResult(
            content=cleaned_text,
            modified=modified,
            findings=findings,
        )

    def reload(self, config_path: str | Path | None = None) -> None:
        """Reload configuration."""
        self._config = load_config(config_path)
        self._pipeline.reload_config(self._config)

    @property
    def config(self) -> GatewayConfig:
        return self._config
