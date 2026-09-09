"""PII detector — detect personally identifiable information in tool responses."""

from __future__ import annotations

import re

from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallResponse,
)
from ..base import OutboundStage
from .content import map_response_text

# PII patterns: (name, regex)
PII_PATTERNS: list[tuple[str, str]] = [
    ("Email Address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    (
        "Phone (International)",
        r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{0,4}",
    ),
    ("SSN (US)", r"\b\d{3}-\d{2}-\d{4}\b"),
    (
        "Credit Card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    ),
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
    ("AHV (Swiss SSN)", r"\b756\.\d{4}\.\d{4}\.\d{2}\b"),
    (
        "IPv4 Address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    ),
]

REDACT_PLACEHOLDER = "[PII REDACTED by mcp-firewall]"


class PIIDetector(OutboundStage):
    """Detect and optionally redact PII in tool responses."""

    stage = PipelineStage.PII_DETECTOR

    def scan(
        self, response: ToolCallResponse, config: GatewayConfig
    ) -> tuple[ToolCallResponse, PipelineDecision | None]:
        if not config.pii.enabled:
            return response, None

        findings: list[str] = []

        def scan_text(text: str) -> str:
            for name, pattern in PII_PATTERNS:
                if re.search(pattern, text):
                    findings.append(name)

                    if config.pii.action == Action.REDACT:
                        text = re.sub(pattern, REDACT_PLACEHOLDER, text)
            return text

        response = map_response_text(response, scan_text)

        if not findings:
            return response, None

        unique = list(dict.fromkeys(findings))
        decision = PipelineDecision(
            stage=self.stage,
            action=config.pii.action,
            reason=f"PII detected: {', '.join(unique)}",
            severity=Severity.MEDIUM,
            details={"pii_types": unique},
        )
        return response, decision
