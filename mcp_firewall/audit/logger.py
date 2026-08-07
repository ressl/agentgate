"""Audit logger — append-only JSON lines with hash chain and optional Ed25519 signing."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

from ..models import Action, AuditEvent, GatewayConfig, PipelineDecision, Severity, ToolCallRequest

_log = logging.getLogger(__name__)


class AuditLogger:
    """Thread-safe append-only audit logger with hash chain integrity and optional signing."""

    def __init__(self, config: GatewayConfig) -> None:
        self.enabled = config.audit.enabled
        self.path = Path(config.audit.path)
        self._lock = threading.Lock()
        self._previous_hash = "genesis"
        self._count = 0
        self._signer = None
        self._max_bytes = max(config.audit.max_size_mb, 0) * 1024 * 1024

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
                    json.loads(last_line)  # validate last line is parseable
                    self._previous_hash = self._hash_entry(last_line)
        except Exception as exc:
            # Corrupt or unreadable log: the chain restarts at "genesis", which
            # makes the break visible to verify_chain instead of hiding it.
            _log.warning("Could not resume audit hash chain from %s: %s", self.path, exc)

    def log(
        self,
        request: ToolCallRequest,
        decision: PipelineDecision | None,
        latency_ms: float = 0.0,
    ) -> None:
        """Log an audit event."""
        if not self.enabled:
            return

        # The whole rotate -> read-hash -> sign -> write -> update-hash sequence
        # must run under the lock, otherwise concurrent log() calls can read the
        # same previous_hash and append entries in the wrong order, breaking the
        # chain.
        with self._lock:
            self._rotate_if_needed()

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

            with open(self.path, "a") as f:
                f.write(line + "\n")
            self._previous_hash = self._hash_entry(line)
            self._count += 1

    def _rotate_if_needed(self) -> None:
        """Rotate the log once it has reached audit.max_size_mb.

        Rotation keeps each file's hash chain intact: the current log is renamed
        to ``<path>.1`` (a single old generation is kept, replacing any previous
        one) and a fresh chain is started. The first entry of the new file is a
        rotation marker whose reason records the hash of the previous chain
        head, so the two generations remain linked. The check runs before each
        append, so a file may overshoot the limit by at most one entry. Must be
        called with the lock held.
        """
        if self._max_bytes <= 0:
            return
        try:
            size = self.path.stat().st_size
        except OSError:
            return  # no log yet
        if size < self._max_bytes:
            return

        rotated = self.path.with_name(self.path.name + ".1")
        self.path.replace(rotated)
        old_head = self._previous_hash
        self._previous_hash = "genesis"
        self._count = 0
        _log.info("Audit log %s rotated to %s (size limit reached)", self.path, rotated)

        marker = AuditEvent(
            agent_id="mcp-firewall",
            tool_name="audit.rotate",
            arguments_hash="",
            decision=Action.ALLOW,
            stage=None,
            reason=f"Audit log rotated; previous chain head: {old_head}",
            severity=Severity.INFO,
            latency_ms=0.0,
            previous_hash="genesis",
        )
        data = json.loads(marker.model_dump_json())
        if self._signer:
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
            data["signature"] = self._signer.sign(canonical)
        line = json.dumps(data, separators=(",", ":"))
        with open(self.path, "a") as f:
            f.write(line + "\n")
        self._previous_hash = self._hash_entry(line)
        self._count += 1

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the hash chain integrity.

        Returns: (is_valid, entries_checked, error_message)
        """
        if not self.path.exists():
            # Distinguishable from an empty-but-present log (which returns
            # (True, 0, "")): a missing file is reported as invalid so callers
            # do not mistake "no log" for "integrity verified".
            return False, 0, f"Audit log file not found: {self.path}"

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
