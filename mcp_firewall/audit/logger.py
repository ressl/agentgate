"""Audit logger — append-only JSON lines with hash chain and optional Ed25519 signing."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

from filelock import FileLock

from ..models import Action, AuditEvent, GatewayConfig, PipelineDecision, Severity, ToolCallRequest

_log = logging.getLogger(__name__)


class AuditLogger:
    """Thread-safe append-only audit logger with hash chain integrity and optional signing."""

    def __init__(self, config: GatewayConfig, *, verification_only: bool = False) -> None:
        self.enabled = config.audit.enabled and not verification_only
        self.path = Path(config.audit.path).expanduser().resolve()
        self._lock = threading.Lock()
        self._file_lock = FileLock(str(self.path) + ".lock")
        self._previous_hash = "genesis"
        self._count = 0
        self._offset = 0
        self._file_id: tuple[int, int] | None = None
        self._last_signed = False
        self._require_signatures = config.audit.sign
        self._signer = None
        self._max_bytes = max(config.audit.max_size_mb, 0) * 1024 * 1024

        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if config.audit.sign:
                from .signer import AuditSigner

                self._signer = AuditSigner()
            # Resume hash chain from last entry
            if self.path.exists():
                with self._file_lock:
                    self._resume_chain()

    def _resume_chain(self) -> None:
        """Resume hash chain from last log entry."""
        try:
            self._sync_chain()
        except Exception as exc:
            # Inspecting the logger remains possible; a subsequent append
            # retries validation and refuses the corrupt tail.
            _log.warning("Could not resume audit hash chain from %s: %s", self.path, exc)

    def _sync_chain(self) -> None:
        """Read only entries appended since our last write, under the process lock."""
        if not self.path.exists():
            self._reset_chain()
            return
        with self.path.open("rb") as stream:
            stat = os.fstat(stream.fileno())
            identity = (stat.st_dev, stat.st_ino)
            if identity != self._file_id or stat.st_size < self._offset:
                self._reset_chain()
            self._file_id = identity
            stream.seek(self._offset)
            for raw in stream:
                if not raw.endswith(b"\n"):
                    raise ValueError("Audit log has an incomplete final entry")
                line = raw.decode("utf-8").strip()
                if line:
                    entry = json.loads(line)
                    if (
                        not isinstance(entry, dict)
                        or entry.get("previous_hash") != self._previous_hash
                    ):
                        raise ValueError("Cannot append to a broken audit chain")
                    self._previous_hash = self._hash_entry(line)
                    self._last_signed = bool(entry.get("signature"))
                    self._count += 1
                self._offset += len(raw)

    def _reset_chain(self) -> None:
        self._previous_hash = "genesis"
        self._count = self._offset = 0
        self._file_id = None
        self._last_signed = False

    def _append(self, event: AuditEvent) -> None:
        data = json.loads(event.model_dump_json())
        if self._signer:
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
            data["signature"] = self._signer.sign(canonical)
        line = json.dumps(data, separators=(",", ":"))
        payload = (line + "\n").encode("utf-8")
        with self.path.open("ab") as stream:
            stream.write(payload)
            stream.flush()
            stat = os.fstat(stream.fileno())
        self._file_id = (stat.st_dev, stat.st_ino)
        self._offset = stat.st_size
        self._previous_hash = self._hash_entry(line)
        self._last_signed = self._signer is not None
        self._count += 1

    def reconfigured(self, config: GatewayConfig) -> AuditLogger:
        """Prepare a new logger; a signing-mode change starts a linked generation."""
        replacement = AuditLogger(config)
        if replacement.enabled:
            with replacement._lock, replacement._file_lock:
                replacement._sync_chain()
                if replacement._count and replacement._last_signed != config.audit.sign:
                    replacement._rotate_if_needed(force=True)
        return replacement

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
        with self._lock, self._file_lock:
            self._sync_chain()
            if self._count and self._last_signed != (self._signer is not None):
                raise ValueError(
                    "Audit signing mode differs from existing log; reload or use a new path"
                )
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

            self._append(event)

    def _rotate_if_needed(self, *, force: bool = False) -> None:
        """Rotate the log once it has reached audit.max_size_mb.

        Rotation keeps each file's hash chain intact: the current log is renamed
        to ``<path>.1`` (a single old generation is kept, replacing any previous
        one) and a fresh chain is started. The first entry of the new file is a
        rotation marker whose reason records the hash of the previous chain
        head, so the two generations remain linked. The check runs before each
        append, so a file may overshoot the limit by at most one entry. Must be
        called with the lock held.
        """
        if self._max_bytes <= 0 and not force:
            return
        try:
            size = self.path.stat().st_size
        except OSError:
            return  # no log yet
        if size < self._max_bytes and not force:
            return

        rotated = self.path.with_name(self.path.name + ".1")
        self.path.replace(rotated)
        old_head = self._previous_hash
        self._reset_chain()
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
        self._append(marker)

    def verify_chain(self, public_key_path: str | Path | None = None) -> tuple[bool, int, str]:
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
        verifier = None

        with self.path.open("rb") as f:
            for line_num, raw in enumerate(f, 1):
                try:
                    line = raw.decode("utf-8").strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                except (ValueError, RecursionError):
                    return False, count, f"Invalid JSON at line {line_num}"

                if not isinstance(entry, dict):
                    return False, count, f"Invalid audit entry at line {line_num}"

                signature = entry.get("signature")
                if self._require_signatures and not signature:
                    return False, count, f"Missing signature at line {line_num}"
                if signature is not None:
                    if verifier is None:
                        from .signer import AuditVerifier

                        try:
                            verifier = AuditVerifier(public_key_path)
                        except (OSError, ValueError) as exc:
                            return False, count, f"Cannot load audit public key: {exc}"
                    canonical = json.dumps(
                        {k: v for k, v in entry.items() if k != "signature"},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    if not verifier.verify(canonical, signature):
                        return False, count, f"Invalid signature at line {line_num}"

                if entry.get("previous_hash") != previous_hash:
                    return (
                        False,
                        count,
                        (
                            f"Hash chain broken at line {line_num}: "
                            f"expected '{previous_hash[:16]}...', "
                            f"got '{str(entry.get('previous_hash', ''))[:16]}...'"
                        ),
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
    def _hash_arguments(arguments: dict[str, Any]) -> str:
        """SHA-256 hash of arguments (privacy-preserving)."""
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]
