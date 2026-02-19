"""Secret scanner — detect leaked credentials in tool responses."""

from __future__ import annotations

import re
from typing import Any

from ..base import OutboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallResponse,
)

# Secret patterns: (name, regex, severity)
SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    # API Keys
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    ("AWS Secret Key", r"(?i)aws_secret_access_key\s*[=:]\s*\S{20,}", Severity.CRITICAL),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}", Severity.CRITICAL),
    ("GitHub PAT (classic)", r"github_pat_[A-Za-z0-9_]{22,}", Severity.CRITICAL),
    ("GitLab Token", r"glpat-[A-Za-z0-9\-_]{20,}", Severity.CRITICAL),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", Severity.CRITICAL),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", Severity.HIGH),
    ("Stripe Key", r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}", Severity.CRITICAL),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}", Severity.HIGH),
    ("Heroku API Key", r"(?i)heroku.*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", Severity.HIGH),

    # Private Keys
    ("Private Key", r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----", Severity.CRITICAL),
    ("SSH Private Key", r"-----BEGIN OPENSSH PRIVATE KEY-----", Severity.CRITICAL),

    # Database URLs
    ("Database URL", r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]+", Severity.CRITICAL),

    # Generic patterns
    ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}", Severity.HIGH),
    ("Basic Auth", r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}", Severity.HIGH),
    ("Password in URL", r"://[^:]+:[^@\s]{3,}@", Severity.CRITICAL),
    ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", Severity.HIGH),
]

REDACT_PLACEHOLDER = "[REDACTED by mcp-firewall]"


class SecretScanner(OutboundStage):
    """Scan tool responses for leaked secrets."""

    stage = PipelineStage.SECRET_SCANNER

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.secrets.enabled:
            return response, None

        findings: list[tuple[str, Severity]] = []
        modified = False

        for i, content_item in enumerate(response.content):
            text = content_item.get("text", "")
            if not text:
                continue

            for name, pattern, severity in SECRET_PATTERNS:
                matches = list(re.finditer(pattern, text))
                if matches:
                    findings.append((name, severity))

                    if config.secrets.action == Action.REDACT:
                        for match in reversed(matches):
                            text = text[: match.start()] + REDACT_PLACEHOLDER + text[match.end() :]
                            modified = True

            if modified:
                response.content[i] = {**content_item, "text": text}

        if not findings:
            return response, None

        worst_severity = max(f[1] for f in findings) if findings else Severity.INFO
        finding_names = ", ".join(f"{name} ({sev.value})" for name, sev in findings)

        if config.secrets.action == Action.DENY:
            decision = PipelineDecision(
                stage=self.stage,
                action=Action.DENY,
                reason=f"Secrets found in response: {finding_names}",
                severity=worst_severity,
            )
            return response, decision

        # REDACT or ALERT
        decision = PipelineDecision(
            stage=self.stage,
            action=config.secrets.action,
            reason=f"Secrets detected and handled: {finding_names}",
            severity=worst_severity,
            details={"findings": [{"name": n, "severity": s.value} for n, s in findings]},
        )
        return response, decision
