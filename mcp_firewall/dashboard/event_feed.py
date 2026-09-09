"""Bounded authenticated event replay for local native integrations."""

from __future__ import annotations

import threading
import uuid
from collections import deque

from pydantic import BaseModel, ConfigDict

from ..models import SecurityEvent


class IntegrationEventPage(BaseModel):
    model_config = ConfigDict(frozen=True)
    stream_id: str
    cursor: int
    oldest_cursor: int
    gap: bool
    has_more: bool
    events: list[SecurityEvent]


class IntegrationEventFeed:
    def __init__(self, capacity: int = 1000) -> None:
        if not 1 <= capacity <= 10000:
            raise ValueError("Invalid event feed capacity")
        self._events: deque[tuple[int, SecurityEvent]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._stream_id = str(uuid.uuid4())
        self._cursor = 0
        self._enabled = False

    def reset(self, *, enabled: bool) -> None:
        with self._lock:
            self._enabled = enabled
            self._events.clear()
            self._cursor = 0
            self._stream_id = str(uuid.uuid4())

    def record(self, event: SecurityEvent) -> None:
        with self._lock:
            if self._enabled:
                self._cursor += 1
                self._events.append((self._cursor, event))

    def read(
        self, *, after: int = 0, stream_id: str | None = None, limit: int = 256
    ) -> IntegrationEventPage:
        with self._lock:
            if stream_id is not None and stream_id != self._stream_id:
                raise LookupError("Event stream restarted; reconnect explicitly")
            if not 0 <= after <= self._cursor or not 1 <= limit <= 256:
                raise ValueError("Invalid event cursor or page size")
            oldest = self._events[0][0] if self._events else self._cursor + 1
            selected = [entry for entry in self._events if entry[0] > after][:limit]
            cursor = selected[-1][0] if selected else after
            return IntegrationEventPage(
                stream_id=self._stream_id,
                cursor=cursor,
                oldest_cursor=oldest,
                gap=after < oldest - 1,
                has_more=cursor < self._cursor,
                events=[event for _, event in selected],
            )


event_feed = IntegrationEventFeed()


def record_integration_event(event: SecurityEvent) -> None:
    """SDK event-handler hook; only enabled with an authenticated controller."""
    event_feed.record(event)
