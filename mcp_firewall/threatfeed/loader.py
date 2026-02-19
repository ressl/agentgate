"""Threat feed rule loader and matcher."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Action, Severity


class ThreatRule:
    """A single threat detection rule."""

    def __init__(
        self,
        id: str,
        name: str,
        severity: Severity,
        description: str,
        match: dict[str, Any],
        action: Action = Action.DENY,
        tags: list[str] | None = None,
    ) -> None:
        self.id = id
        self.name = name
        self.severity = severity
        self.description = description
        self.match = match
        self.action = action
        self.tags = tags or []
        self._compiled_patterns: dict[str, re.Pattern] = {}
        self._compile()

    def _compile(self) -> None:
        """Pre-compile regex patterns for performance."""
        args = self.match.get("arguments", {})
        for key, pattern in args.items():
            if isinstance(pattern, str):
                # Convert glob-like patterns to regex
                regex = pattern.replace("*", ".*").replace("?", ".")
                try:
                    self._compiled_patterns[key] = re.compile(regex, re.IGNORECASE)
                except re.error:
                    pass

        # Tool name pattern
        tool_pattern = self.match.get("tool")
        if tool_pattern:
            regex = tool_pattern.replace("*", ".*").replace("|", "|")
            try:
                self._compiled_patterns["__tool__"] = re.compile(f"^({regex})$", re.IGNORECASE)
            except re.error:
                pass

    def matches(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """Check if a tool call matches this rule."""
        # Check tool name
        tool_pattern = self._compiled_patterns.get("__tool__")
        if tool_pattern and not tool_pattern.match(tool_name):
            return False

        # Check argument patterns
        arg_matchers = self.match.get("arguments", {})
        for key, _ in arg_matchers.items():
            value = arguments.get(key)
            if value is None:
                # Also check nested/stringified arguments
                value = _find_in_args(key, arguments)
                if value is None:
                    return False

            compiled = self._compiled_patterns.get(key)
            if compiled and isinstance(value, str):
                if not compiled.search(value):
                    return False

        # Check description patterns (match against all string values)
        desc_pattern = self.match.get("description")
        if desc_pattern:
            all_text = " ".join(str(v) for v in arguments.values())
            if not re.search(desc_pattern, all_text, re.IGNORECASE):
                return False

        return True


class ThreatFeed:
    """Load and manage threat detection rules."""

    def __init__(self) -> None:
        self.rules: list[ThreatRule] = []

    def load_directory(self, path: str | Path) -> int:
        """Load all YAML rules from a directory. Returns count loaded."""
        path = Path(path)
        if not path.exists():
            return 0

        count = 0
        for yaml_file in sorted(path.glob("*.yaml")):
            try:
                self.load_file(yaml_file)
                count += 1
            except Exception:
                pass
        return count

    def load_file(self, path: str | Path) -> ThreatRule:
        """Load a single rule file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        rule = ThreatRule(
            id=data["id"],
            name=data["name"],
            severity=Severity(data.get("severity", "medium")),
            description=data.get("description", ""),
            match=data.get("match", {}),
            action=Action(data.get("action", "deny")),
            tags=data.get("tags", []),
        )
        self.rules.append(rule)
        return rule

    def check(self, tool_name: str, arguments: dict[str, Any]) -> ThreatRule | None:
        """Check a tool call against all rules. Returns first match or None."""
        for rule in self.rules:
            if rule.matches(tool_name, arguments):
                return rule
        return None

    def list_rules(self) -> list[dict[str, str]]:
        """List all loaded rules."""
        return [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "description": r.description,
                "tags": ", ".join(r.tags),
            }
            for r in self.rules
        ]


def _find_in_args(key: str, args: dict[str, Any], depth: int = 0) -> str | None:
    """Recursively search for a key in nested arguments."""
    if depth > 3:
        return None
    for k, v in args.items():
        if k == key:
            return str(v) if v is not None else None
        if isinstance(v, dict):
            found = _find_in_args(key, v, depth + 1)
            if found:
                return found
    return None
