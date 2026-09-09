"""Bounded, single-use human approvals for trusted local controller adapters."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from .events import sanitize_text
from .models import ToolCallRequest

MAX_REQUEST_BYTES = 16_384
_SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|api.?key|authorization|credential|private.?key|cookie",
    re.IGNORECASE,
)


class PendingApproval(BaseModel):
    """Sanitized controller view; the hash binds the complete original request."""

    model_config = ConfigDict(frozen=True)
    id: str
    session_id: str
    call_id: str
    request_hash: str
    tool: str
    agent: str
    arguments_preview: str
    redacted: bool
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class ApprovalOutcome:
    approved: bool
    reason: str


@dataclass
class _Pending:
    view: PendingApproval
    request: ToolCallRequest
    deadline: float
    cancel_events: tuple[threading.Event, ...]
    outcome: ApprovalOutcome | None = None


def _snapshot(request: ToolCallRequest, session_id: str) -> bytes:
    data = json.dumps(
        [session_id, request.call_id, request.tool_name, request.agent_id, request.arguments],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("Approval request exceeds preview limit")
    return data


def _preview(value: Any, depth: int = 0) -> Any:
    if depth > 20:
        raise ValueError("Approval request exceeds nesting limit")
    if isinstance(value, str):
        if len(value) > 1024:
            raise ValueError("Approval field exceeds preview limit")
        return sanitize_text(value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = _preview(key, depth + 1)
            if safe_key in result:
                raise ValueError("Redacted keys would hide an approval argument")
            result[safe_key] = (
                "[REDACTED]" if _SENSITIVE_KEY.search(key) else _preview(item, depth + 1)
            )
        return result
    if isinstance(value, list):
        return [_preview(item, depth + 1) for item in value]
    return value


class ApprovalBroker:
    """Thread-safe broker. Only an authenticated controller should call pending/decide.

    Polling renews a controller lease. No controller, expiration, cancellation or
    shutdown denies the call. This object never executes tools or overrides policy.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 60,
        controller_timeout: float = 10,
        max_pending: int = 32,
    ) -> None:
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 300:
            raise ValueError("Approval timeout must be between 0 and 300 seconds")
        if not math.isfinite(controller_timeout) or not 0 < controller_timeout <= 60:
            raise ValueError("Controller timeout must be between 0 and 60 seconds")
        if type(max_pending) is not int or not 1 <= max_pending <= 1000:
            raise ValueError("Pending approval capacity must be between 1 and 1000")
        self.timeout_seconds = timeout_seconds
        self.controller_timeout = controller_timeout
        self.max_pending = max_pending
        self._condition = threading.Condition()
        self._pending: dict[str, _Pending] = {}
        self._controller_seen: float | None = None
        self._closed = False

    def _finish(self, item: _Pending, approved: bool, reason: str) -> None:
        item.outcome = ApprovalOutcome(approved, f"{reason} (approval {item.view.id})")
        self._pending.pop(item.view.id, None)
        self._condition.notify_all()

    def _expire(self) -> None:
        now = time.monotonic()
        connected = (
            self._controller_seen is not None
            and now < self._controller_seen + self.controller_timeout
        )
        for item in list(self._pending.values()):
            if self._closed or any(event.is_set() for event in item.cancel_events):
                self._finish(item, False, "Approval cancelled")
            elif not connected:
                self._finish(item, False, "Approval controller disconnected")
            elif now >= item.deadline:
                self._finish(item, False, "Approval timed out")
        if not connected:
            self._controller_seen = None

    def pending(self) -> list[PendingApproval]:
        """Read sanitized pending calls and renew the controller lease."""
        with self._condition:
            self._expire()  # Renewing must never resurrect an expired request.
            if not self._closed:
                self._controller_seen = time.monotonic()
            return [item.view for item in self._pending.values()]

    def _create(
        self,
        request: ToolCallRequest,
        session_id: str,
        cancel_events: tuple[threading.Event, ...],
    ) -> _Pending | ApprovalOutcome:
        with self._condition:
            self._expire()
            if self._closed or any(event.is_set() for event in cancel_events):
                return ApprovalOutcome(False, "Approval cancelled")
            if self._controller_seen is None:
                return ApprovalOutcome(False, "No approval controller connected")
            if len(self._pending) >= self.max_pending:
                return ApprovalOutcome(False, "Pending approval capacity reached")
            try:
                snapshot = _snapshot(request, session_id)
                _, call_id, tool, agent, arguments = json.loads(snapshot)
                safe_tool, safe_agent = _preview(tool), _preview(agent)
                safe_arguments = _preview(arguments)
                preview = json.dumps(safe_arguments, indent=2, ensure_ascii=True)
                if len(preview.encode()) > MAX_REQUEST_BYTES:
                    raise ValueError("Approval preview too large")
            except (ValueError, TypeError, RecursionError, OverflowError):
                return ApprovalOutcome(False, "Request cannot be safely previewed for approval")
            created = time.time()
            view = PendingApproval(
                id=str(uuid.uuid4()),
                session_id=session_id,
                call_id=call_id,
                request_hash=hashlib.sha256(snapshot).hexdigest(),
                tool=safe_tool,
                agent=safe_agent,
                arguments_preview=preview,
                redacted=(safe_arguments != arguments or safe_tool != tool or safe_agent != agent),
                created_at=created,
                expires_at=created + self.timeout_seconds,
            )
            item = _Pending(view, request, time.monotonic() + self.timeout_seconds, cancel_events)
            self._pending[view.id] = item
            return item

    @staticmethod
    def _unchanged(item: _Pending) -> bool:
        try:
            digest = hashlib.sha256(_snapshot(item.request, item.view.session_id)).hexdigest()
            return hmac.compare_digest(digest, item.view.request_hash)
        except (ValueError, TypeError, RecursionError, OverflowError):
            return False

    def decide(self, approval_id: str, request_hash: str, allow: bool) -> None:
        """Consume a pending request with its exact binding; stale decisions fail."""
        if type(allow) is not bool:
            raise ValueError("Approval decision must be boolean")
        with self._condition:
            self._expire()
            item = self._pending.get(approval_id)
            if item is None:
                raise LookupError("Approval expired or already consumed")
            if not hmac.compare_digest(item.view.request_hash, request_hash):
                raise ValueError("Approval binding mismatch")
            if not self._unchanged(item):
                self._finish(item, False, "Approval request changed")
                raise ValueError("Approval request changed")
            self._finish(item, allow, "User approved once" if allow else "User denied")

    def _wait(self, item: _Pending) -> ApprovalOutcome:
        with self._condition:
            while item.outcome is None:
                self._expire()
                if item.outcome is None:
                    lease_end = (self._controller_seen or 0) + self.controller_timeout
                    self._condition.wait(max(0, min(item.deadline, lease_end) - time.monotonic()))
            if item.outcome.approved and (
                self._closed
                or any(event.is_set() for event in item.cancel_events)
                or not self._unchanged(item)
            ):
                return ApprovalOutcome(False, "Approval cancelled or request changed")
            return item.outcome

    def request(
        self,
        request: ToolCallRequest,
        session_id: str,
        *,
        cancel_events: tuple[threading.Event, ...] = (),
    ) -> ApprovalOutcome:
        item = self._create(request, session_id, cancel_events)
        return item if isinstance(item, ApprovalOutcome) else self._wait(item)

    async def arequest(
        self,
        request: ToolCallRequest,
        session_id: str,
        *,
        cancel_events: tuple[threading.Event, ...] = (),
    ) -> ApprovalOutcome:
        # Register before yielding so cancellation cannot leave a late worker request.
        item = self._create(request, session_id, cancel_events)
        if isinstance(item, ApprovalOutcome):
            return item
        try:
            return await asyncio.to_thread(self._wait, item)
        except asyncio.CancelledError:
            with self._condition:
                self._finish(item, False, "Approval cancelled")
            raise

    def wake(self) -> None:
        """Wake waiters after a caller sets a cancellation event."""
        with self._condition:
            self._expire()
            self._condition.notify_all()

    def cancel_session(self, session_id: str) -> None:
        with self._condition:
            for item in list(self._pending.values()):
                if item.view.session_id == session_id:
                    self._finish(item, False, "Approval session closed")

    def disconnect(self) -> None:
        with self._condition:
            self._controller_seen = None
            self._expire()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._expire()
