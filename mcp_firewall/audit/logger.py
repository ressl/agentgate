"""Audit logger — append-only JSON lines with hash chain and optional Ed25519 signing."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

from ..models import Action, AuditEvent, GatewayConfig, PipelineDecision, Severity, ToolCallRequest


class AuditLogger:
    """Thread-safe append-only audit logger with hash chain integrity and optional signing."""

    def __init__(self, config: GatewayConfig) -> None:
        self.enabled = config.audit.enabled
        self.path = Path(config.audit.path)
        self._lock = threading.Lock()
        self._previous_hash = "genesis"
        self._count = 0
        self._signer = None

        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if config.audit.sign:
                from .signer import AuditSigner
                self._signer = AuditSigner()
            # Resume hash chain from last entry
            if self.path.exists():
                self._resume_chain()

    def _resume_chain(self) -> None:
        """Resume hash chain from last log entry."""
        try:
            with open(self.path) as f:
                last_line = ""
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
                        self._count += 1
                if last_line:
                    entry = json.loads(last_line)
                    self._previous_hash = self._hash_entry(last_line)
        except Exception:
            pass

    def log(
        self,
        request: ToolCallRequest,
        decision: PipelineDecision | None,
        latency_ms: float = 0.0,
    ) -> None:
        """Log an audit event."""
        if not self.enabled:
            return

        event = AuditEvent(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            arguments_hash=self._hash_arguments(request.arguments),
            decision=decision.action if decision else Action.ALLOW,
            stage=decision.stage if decision else None,
            reason=decision.reason if decision else "",
            severity=decision.severity if decision else Severity.INFO,
            latency_ms=latency_ms,
            previous_hash=self._previous_hash,
        )

        data = json.loads(event.model_dump_json())

        # Add signature if signing is enabled
        if self._signer:
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
            data["signature"] = self._signer.sign(canonical)

        line = json.dumps(data, separators=(",", ":"))

        with self._lock:
            with open(self.path, "a") as f:
                f.write(line + "\n")
            self._previous_hash = self._hash_entry(line)
            self._count += 1

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the hash chain integrity.

        Returns: (is_valid, entries_checked, error_message)
        """
        if not self.path.exists():
            return True, 0, ""

        previous_hash = "genesis"
        count = 0

        with open(self.path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, count, f"Invalid JSON at line {line_num}"

                if entry.get("previous_hash") != previous_hash:
                    return False, count, (
                        f"Hash chain broken at line {line_num}: "
                        f"expected '{previous_hash[:16]}...', "
                        f"got '{entry.get('previous_hash', '')[:16]}...'"
                    )

                previous_hash = self._hash_entry(line)
                count += 1

        return True, count, ""

    @property
    def entry_count(self) -> int:
        return self._count

    @staticmethod
    def _hash_entry(line: str) -> str:
        """SHA-256 hash of a log line."""
        return hashlib.sha256(line.encode()).hexdigest()

    @staticmethod
    def _hash_arguments(arguments: dict) -> str:
        """SHA-256 hash of arguments (privacy-preserving)."""
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]
