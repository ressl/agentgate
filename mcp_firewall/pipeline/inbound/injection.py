"""Injection detection — detect prompt injection in tool arguments."""

from __future__ import annotations

import json
import re
from typing import Any

from ..base import InboundStage
from ...models import (
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)

# Patterns organized by sensitivity level
PATTERNS_LOW = [
    (r"ignore\s+(all\s+)?previous\s+instructions", "Instruction override"),
    (r"you\s+are\s+now\s+in\s+(\w+\s+)?mode", "Role reassignment"),
    (r"system:\s*you\s+are", "System prompt injection"),
    (r"<\|im_start\|>|<\|im_end\|>", "Chat template injection"),
    (r"\[INST\]|\[/INST\]", "Llama template injection"),
]

PATTERNS_MEDIUM = PATTERNS_LOW + [
    (r"do\s+not\s+follow\s+(any\s+)?(previous|prior|above)", "Instruction negation"),
    (r"forget\s+(everything|all|your)\s+(previous|prior)?", "Memory wipe attempt"),
    (r"pretend\s+(you\s+are|to\s+be|you're)", "Persona hijack"),
    (r"act\s+as\s+(a\s+)?(\w+)", "Role impersonation"),
    (r"output\s+the\s+(system|initial)\s+prompt", "Prompt extraction"),
    (r"repeat\s+(the\s+)?(above|system|initial)\s+(text|prompt|instructions)", "Prompt leak"),
    (r"<!--.*?-->", "HTML comment (hidden instructions)"),
    (r"base64[:\s]|atob\(|btoa\(", "Base64 obfuscation"),
]

PATTERNS_HIGH = PATTERNS_MEDIUM + [
    (r"please\s+(always|never|only)", "Behavioral override"),
    (r"important:\s", "Priority escalation"),
    (r"ADMIN|ROOT|SUDO|SUPERUSER", "Privilege keyword"),
    (r"override|bypass|skip|disable", "Control bypass"),
    (r"[\u200b\u200c\u200d\u2060\ufeff]", "Invisible Unicode"),
]

SENSITIVITY_MAP = {
    "low": PATTERNS_LOW,
    "medium": PATTERNS_MEDIUM,
    "high": PATTERNS_HIGH,
}


class InjectionDetector(InboundStage):
    """Detect prompt injection patterns in tool call arguments."""

    stage = PipelineStage.INJECTION

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.injection.enabled:
            return None

        patterns = SENSITIVITY_MAP.get(config.injection.sensitivity, PATTERNS_MEDIUM)

        # Flatten all argument values into searchable strings
        text = _flatten_arguments(request.arguments)

        for pattern, label in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return self._deny(
                    f"Prompt injection detected: {label}",
                    severity=Severity.CRITICAL,
                    details={"pattern": label, "matched": match.group()[:100]},
                )

        return None


def _flatten_arguments(args: dict[str, Any], depth: int = 0) -> str:
    """Recursively flatten arguments to a single searchable string."""
    if depth > 5:
        return ""

    parts: list[str] = []
    for key, value in args.items():
        parts.append(str(key))
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            parts.append(_flatten_arguments(value, depth + 1))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(_flatten_arguments(item, depth + 1))
                else:
                    parts.append(str(item))
        else:
            parts.append(str(value))

    return " ".join(parts)
