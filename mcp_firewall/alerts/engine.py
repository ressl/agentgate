"""Alert engine — route pipeline decisions to notification channels."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..models import Action, PipelineDecision, Severity, ToolCallRequest

logger = logging.getLogger("mcp_firewall.alerts")


class AlertChannel:
    """Base class for alert notification channels."""

    name: str = "base"

    async def send(self, alert: AlertEvent) -> bool:
        """Send alert. Returns True on success."""
        raise NotImplementedError


class AlertEvent:
    """Structured alert event."""

    def __init__(
        self,
        request: ToolCallRequest,
        decision: PipelineDecision,
    ) -> None:
        self.request = request
        self.decision = decision

    @property
    def severity(self) -> Severity:
        return self.decision.severity

    @property
    def title(self) -> str:
        return f"[{self.decision.severity.value.upper()}] {self.decision.stage.value if self.decision.stage else 'unknown'}"

    @property
    def message(self) -> str:
        return (
            f"**Tool:** {self.request.tool_name}\n"
            f"**Agent:** {self.request.agent_id}\n"
            f"**Action:** {self.decision.action.value}\n"
            f"**Reason:** {self.decision.reason}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.decision.severity.value,
            "stage": self.decision.stage.value if self.decision.stage else None,
            "action": self.decision.action.value,
            "tool": self.request.tool_name,
            "agent": self.request.agent_id,
            "reason": self.decision.reason,
            "timestamp": self.request.timestamp,
        }


class AlertEngine:
    """Routes alerts to configured channels based on severity threshold."""

    def __init__(
        self,
        channels: list[AlertChannel] | None = None,
        min_severity: Severity = Severity.HIGH,
    ) -> None:
        self.channels = channels or []
        self.min_severity = min_severity
        self._history: list[AlertEvent] = []

    def process(self, request: ToolCallRequest, decision: PipelineDecision) -> None:
        """Process a pipeline decision and fire alerts if needed."""
        if decision.action not in (Action.DENY, Action.ALERT):
            return

        if decision.severity < self.min_severity:
            return

        event = AlertEvent(request, decision)
        self._history.append(event)

        # Trim history
        if len(self._history) > 10000:
            self._history = self._history[-5000:]

        # Fire alerts async (best-effort)
        try:
            loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        for channel in self.channels:
            if loop is not None:
                task = loop.create_task(channel.send(event))
                task.add_done_callback(self._log_task_failure)
            else:
                # No running event loop: send synchronously so the alert is not lost
                try:
                    asyncio.run(channel.send(event))
                except Exception as e:
                    logger.warning(f"Alert channel {channel.name} failed: {e}")

    def close(self) -> None:
        """Close channels that hold resources (e.g. shared HTTP clients).

        Channels recreate their clients lazily, so closing is always safe —
        even for channels that stay in use afterwards.
        """
        try:
            loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        for channel in self.channels:
            close_fn = getattr(channel, "close", None)
            if close_fn is None:
                continue
            try:
                if loop is not None:
                    task = loop.create_task(close_fn())
                    task.add_done_callback(self._log_task_failure)
                else:
                    asyncio.run(close_fn())
            except Exception as e:
                logger.warning(f"Alert channel {channel.name} close failed: {e}")

    @staticmethod
    def _log_task_failure(task: asyncio.Task) -> None:
        """Retrieve and log exceptions from fire-and-forget alert tasks."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.warning(f"Alert send task failed: {exc}")

    @property
    def history(self) -> list[AlertEvent]:
        return self._history
