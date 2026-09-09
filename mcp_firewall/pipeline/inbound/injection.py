"""Injection detection — detect prompt injection in tool arguments."""

from __future__ import annotations

import re
from typing import Any

from ...models import (
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)
from ..base import InboundStage

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
    (r"\b(?:ADMIN|ROOT|SUDO|SUPERUSER)\b", "Privilege keyword"),
    (r"\b(?:override|bypass|skip|disable)\b", "Control bypass"),
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


# Maximum nesting depth searched when flattening arguments. Deeply nested
# payloads beyond this bound are skipped; the bound also keeps cyclic
# structures from looping forever.
MAX_FLATTEN_DEPTH = 20


def _flatten_arguments(args: dict[str, Any], max_depth: int = MAX_FLATTEN_DEPTH) -> str:
    """Flatten arguments to a single searchable string (iterative, bounded)."""
    parts: list[str] = []
    stack: list[tuple[Any, int]] = [(args, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > max_depth:
            continue
        if isinstance(value, dict):
            for key, item in value.items():
                parts.append(str(key))
                stack.append((item, depth + 1))
        elif isinstance(value, (list, tuple)):
            stack.extend((item, depth + 1) for item in value)
        else:
            parts.append(str(value))

    return " ".join(parts)
