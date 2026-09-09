"""Versioned lifecycle events and bounded, non-blocking observer delivery."""

from __future__ import annotations

import logging
import queue
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace

import httpx

from .models import (
    Action,
    EventPhase,
    EventsConfig,
    EventWebhookConfig,
    PipelineDecision,
    SecurityEvent,
    Severity,
    ToolCallRequest,
)
from .pipeline.outbound.pii import PII_PATTERNS
from .pipeline.outbound.secrets import SECRET_PATTERNS

logger = logging.getLogger("mcp_firewall.events")
EventHandler = Callable[[SecurityEvent], None]
_PATTERNS = [re.compile(pattern) for _, pattern, _ in SECRET_PATTERNS]
_PATTERNS += [re.compile(pattern) for _, pattern in PII_PATTERNS]
_PATTERNS.append(
    re.compile(
        r"(?i)\b(?:password|passwd|api[_-]?key|secret|token)\s*[=:]\s*"
        r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
    )
)


def sanitize_text(value: str) -> str:
    """Scrub known patterns before export, independently of response policy."""
    # Omit oversized fields wholesale: truncation can split a secret's marker.
    if len(value) > 1024:
        return "[OMITTED: field exceeds export limit]"
    for pattern in _PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    return value[:1024]


@dataclass
class DeliveryStats:
    enqueued: int = 0
    delivered: int = 0
    failed: int = 0
    dropped: int = 0
    queued: int = 0
    in_flight: int = 0


class EventDispatcher:
    """One daemon worker, bounded memory, bounded close, no observer on caller loop.

    Handlers are trusted application code. A blocked Python callback cannot be
    forcibly killed; close reports in-flight work and returns at its deadline.
    """

    def __init__(self, handlers: list[EventHandler], capacity: int = 256) -> None:
        if capacity < 1:
            raise ValueError("Event queue capacity must be positive")
        self._handlers = tuple(handlers)
        self._queue: queue.Queue[SecurityEvent] = queue.Queue(maxsize=capacity)
        self._lock = threading.Lock()
        self._stats = DeliveryStats()
        self._closed = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def stats(self) -> DeliveryStats:
        with self._lock:
            return replace(self._stats, queued=self._queue.qsize())

    @property
    def idle(self) -> bool:
        with self._queue.mutex:
            return self._queue.unfinished_tasks == 0

    def publish(self, event: SecurityEvent) -> bool:
        with self._lock:
            if self._closed.is_set():
                self._stats.dropped += 1
                return False
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                self._stats.dropped += 1
                # Bound diagnostics too; an attacker cannot print one line per call.
                if self._stats.dropped == 1 or self._stats.dropped % 100 == 0:
                    logger.warning("Event queue full; dropped events: %d", self._stats.dropped)
                return False
            self._stats.enqueued += 1
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._run, name="mcp-firewall-events", daemon=True
                )
                self._thread.start()
        return True

    def _run(self) -> None:
        try:
            while not self._closed.is_set() or not self._queue.empty():
                try:
                    event = self._queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                with self._lock:
                    self._stats.in_flight = 1
                failed = False
                for handler in self._handlers:
                    try:
                        handler(event)
                    except Exception:
                        failed = True
                        # Exceptions may contain URLs, credentials, or response bodies.
                        with self._lock:
                            failures = self._stats.failed
                        if failures == 0 or (failures + 1) % 100 == 0:
                            logger.warning("Event observer delivery failed (event %s)", event.id)
                with self._lock:
                    if failed:
                        self._stats.failed += 1
                    else:
                        self._stats.delivered += 1
                    self._stats.in_flight = 0
                self._queue.task_done()
        finally:
            for handler in self._handlers:
                close = getattr(handler, "close", None)
                if close is not None:
                    try:
                        close()
                    except Exception:
                        logger.warning("Event observer cleanup failed")

    def close(self, timeout: float = 5) -> DeliveryStats:
        with self._lock:
            self._closed.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0, timeout))
        if thread is not None and thread.is_alive():
            with self._lock:
                while True:
                    try:
                        self._queue.get_nowait()
                    except queue.Empty:
                        break
                    self._queue.task_done()
                    self._stats.dropped += 1
            logger.warning("Event shutdown deadline reached; delivery may be incomplete")
        return self.stats


class EventWebhook:
    """Synchronous HTTP sender used only by the dispatcher worker."""

    def __init__(self, config: EventWebhookConfig) -> None:
        self.config = config.model_copy(deep=True)
        self._client: httpx.Client | None = None

    def __call__(self, event: SecurityEvent) -> None:
        if self._client is None:
            self._client = httpx.Client(
                timeout=self.config.timeout_seconds,
                trust_env=False,
                follow_redirects=False,
            )
        payload = {"source": "mcp-firewall", "event": event.model_dump(mode="json")}
        for attempt in range(self.config.max_retries + 1):
            transient = True
            try:
                headers = {
                    key: value
                    for key, value in self.config.headers.items()
                    if key.lower() != "idempotency-key"
                }
                # Inspect only status/headers; a receiver cannot force us to buffer
                # or drain an unbounded response body.
                with self._client.stream(
                    "POST",
                    self.config.url,
                    json=payload,
                    headers={**headers, "Idempotency-Key": event.id},
                ) as response:
                    if response.is_success:
                        return
                    transient = response.status_code == 429 or response.status_code >= 500
            except httpx.TransportError:
                pass
            if not transient or attempt == self.config.max_retries:
                raise RuntimeError("Event webhook delivery failed")
            time.sleep(0.1 * (2**attempt))

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


class EventEmitter:
    """Owns session/sequence identity and sanitizes every public event."""

    def __init__(
        self,
        config: EventsConfig,
        *,
        handler: EventHandler | None = None,
        observer: EventHandler | None = None,
    ) -> None:
        self.session_id = str(uuid.uuid4())
        self._sequence = 0
        self._lock = threading.Lock()
        self._handler = handler
        # Only a trusted, bounded internal adapter (dashboard); user handlers queue.
        self._observer = observer
        self._config = config.model_copy(deep=True)
        self._dispatcher = self._build_dispatcher(config)
        self._previous_stats = DeliveryStats()

    def _build_dispatcher(self, config: EventsConfig) -> EventDispatcher | None:
        handlers = [self._handler] if self._handler else []
        if config.enabled and config.webhook is not None:
            handlers.append(EventWebhook(config.webhook))
        return EventDispatcher(handlers, config.queue_size) if handlers else None

    def emit(
        self,
        request: ToolCallRequest,
        phase: EventPhase,
        decision: PipelineDecision | None = None,
        *,
        reason: str = "",
        response_is_error: bool | None = None,
    ) -> SecurityEvent:
        with self._lock:
            self._sequence += 1
            protocol_id = request.protocol_id
            event = SecurityEvent(
                session_id=self.session_id,
                call_id=request.call_id,
                request_id=sanitize_text(protocol_id)
                if isinstance(protocol_id, str)
                else protocol_id,
                correlated=request.correlated,
                sequence=self._sequence,
                phase=phase,
                response_is_error=response_is_error,
                tool=sanitize_text(request.tool_name),
                agent=sanitize_text(request.agent_id),
                action=decision.action if decision else self._phase_action(phase),
                severity=decision.severity if decision else Severity.INFO,
                stage=decision.stage if decision else None,
                reason=sanitize_text(decision.reason if decision else reason),
            )
            if self._dispatcher is not None:
                self._dispatcher.publish(event)
            if self._observer is not None:
                try:
                    self._observer(event)
                except Exception:
                    logger.warning("Internal event observer failed")
            return event

    @staticmethod
    def _phase_action(phase: EventPhase) -> Action | None:
        if phase in {EventPhase.REQUEST_ALLOWED, EventPhase.RESPONSE_ALLOWED}:
            return Action.ALLOW
        if phase in {EventPhase.REQUEST_DENIED, EventPhase.RESPONSE_DENIED}:
            return Action.DENY
        if phase == EventPhase.RESPONSE_REDACTED:
            return Action.REDACT
        return None

    @property
    def stats(self) -> DeliveryStats:
        current = self._dispatcher.stats if self._dispatcher else DeliveryStats()
        for field in ("enqueued", "delivered", "failed", "dropped"):
            setattr(current, field, getattr(current, field) + getattr(self._previous_stats, field))
        return current

    def reconfigure(self, config: EventsConfig) -> None:
        with self._lock:
            if config == self._config:
                return
            if self._dispatcher is not None and not self._dispatcher.idle:
                raise ValueError(
                    "Event delivery is busy; retry changing event settings after delivery drains"
                )
            replacement = self._build_dispatcher(config)
            previous = self._dispatcher
            self._previous_stats = self.stats
            self._dispatcher = replacement
            timeout = self._config.shutdown_timeout
            self._config = config.model_copy(deep=True)
        if previous is not None:
            previous.close(timeout)

    def close(self) -> DeliveryStats:
        if self._dispatcher is not None:
            self._dispatcher.close(self._config.shutdown_timeout)
        return self.stats
