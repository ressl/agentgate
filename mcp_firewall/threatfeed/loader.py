"""Threat feed rule loader and matcher."""

from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from ..models import Action, Severity

logger = logging.getLogger(__name__)


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
        self._compile_failed = False
        self._compile()

    def _compile(self) -> None:
        """Pre-compile match patterns for performance.

        Patterns use glob syntax (``|`` separates alternatives). A rule with an
        invalid or non-string pattern is disabled (fail-closed) so it can never
        match every request.
        """
        args = self.match.get("arguments", {})
        for key, pattern in args.items():
            if not isinstance(pattern, str):
                logger.warning(
                    "Threat rule %s: non-string pattern for argument '%s', rule disabled",
                    self.id, key,
                )
                self._compile_failed = True
                continue
            try:
                self._compiled_patterns[key] = re.compile(
                    _glob_to_regex(pattern), re.IGNORECASE
                )
            except re.error:
                logger.warning(
                    "Threat rule %s: invalid pattern for argument '%s', rule disabled",
                    self.id, key,
                )
                self._compile_failed = True

        # Tool name pattern
        tool_pattern = self.match.get("tool")
        if tool_pattern:
            try:
                self._compiled_patterns["__tool__"] = re.compile(
                    _glob_to_regex(tool_pattern), re.IGNORECASE
                )
            except re.error:
                logger.warning(
                    "Threat rule %s: invalid tool pattern, rule disabled", self.id
                )
                self._compile_failed = True

        # Description pattern (raw regex, matched against all argument values)
        desc_pattern = self.match.get("description")
        if desc_pattern:
            try:
                self._compiled_patterns["__description__"] = re.compile(
                    desc_pattern, re.IGNORECASE
                )
            except re.error:
                logger.warning(
                    "Threat rule %s: invalid description pattern, rule disabled", self.id
                )
                self._compile_failed = True

    def matches(self, tool_name: str, arguments: dict[str, Any]) -> bool:
        """Check if a tool call matches this rule."""
        if self._compile_failed:
            # Fail closed: a broken rule must never match
            return False

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
            if compiled:
                if not isinstance(value, str):
                    value = str(value)
                if not compiled.match(value):
                    return False

        # Check description patterns (match against all string values)
        desc_pattern = self._compiled_patterns.get("__description__")
        if desc_pattern:
            all_text = " ".join(str(v) for v in arguments.values())
            if not desc_pattern.search(all_text):
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


def _glob_to_regex(pattern: str) -> str:
    """Translate a glob pattern with ``|`` alternatives into a single regex."""
    alternatives = [fnmatch.translate(part) for part in pattern.split("|")]
    if len(alternatives) == 1:
        return alternatives[0]
    return "(?:" + "|".join(alternatives) + ")"


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
