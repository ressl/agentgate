"""Tests for code-review fixes: alerts (M15, L4, L10)."""

from __future__ import annotations

import asyncio
import logging

from mcp_firewall.alerts.engine import AlertChannel, AlertEngine, AlertEvent
from mcp_firewall.alerts.slack import SlackChannel
from mcp_firewall.alerts.syslog import (
    SyslogChannel,
    _cef_escape_extension,
    _cef_escape_header,
)
from mcp_firewall.alerts.webhook import WebhookChannel
from mcp_firewall.models import (
    Action,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)


def make_request(tool: str = "exec", agent: str = "test") -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, agent_id=agent)


def make_decision(
    action: Action = Action.DENY,
    severity: Severity = Severity.HIGH,
    reason: str = "test alert",
) -> PipelineDecision:
    return PipelineDecision(
        stage=PipelineStage.INJECTION,
        action=action,
        severity=severity,
        reason=reason,
    )


class RecordingChannel(AlertChannel):
    name = "recording"

    def __init__(self) -> None:
        self.events: list[AlertEvent] = []

    async def send(self, alert: AlertEvent) -> bool:
        self.events.append(alert)
        return True


class FailingChannel(AlertChannel):
    name = "failing"

    async def send(self, alert: AlertEvent) -> bool:
        raise RuntimeError("boom")


# --- M15: alerts must not be silently lost ---

class TestNoRunningLoop:
    def test_sync_fallback_without_any_loop(self):
        channel = RecordingChannel()
        engine = AlertEngine(channels=[channel], min_severity=Severity.LOW)
        engine.process(make_request(), make_decision())
        assert len(channel.events) == 1

    def test_sync_fallback_with_set_but_not_running_loop(self):
        # M15 regression: a loop is set on the thread but never runs.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            channel = RecordingChannel()
            engine = AlertEngine(channels=[channel], min_severity=Severity.LOW)
            engine.process(make_request(), make_decision())
            assert len(channel.events) == 1
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def test_sync_fallback_logs_channel_failure(self, caplog):
        channel = FailingChannel()
        engine = AlertEngine(channels=[channel], min_severity=Severity.LOW)
        with caplog.at_level(logging.WARNING, logger="mcp_firewall.alerts"):
            engine.process(make_request(), make_decision())
        assert "failing" in caplog.text


class TestRunningLoop:
    async def test_task_created_on_running_loop(self):
        channel = RecordingChannel()
        engine = AlertEngine(channels=[channel], min_severity=Severity.LOW)
        engine.process(make_request(), make_decision())
        await asyncio.sleep(0)
        assert len(channel.events) == 1

    async def test_task_exception_is_retrieved_and_logged(self, caplog):
        channel = FailingChannel()
        engine = AlertEngine(channels=[channel], min_severity=Severity.LOW)
        with caplog.at_level(logging.WARNING, logger="mcp_firewall.alerts"):
            engine.process(make_request(), make_decision())
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        assert "boom" in caplog.text


# --- L4: CEF escaping ---

class TestCefEscaping:
    def test_header_escapes_backslash_pipe_newlines(self):
        assert _cef_escape_header("a|b") == "a\\|b"
        assert _cef_escape_header("a\\b") == "a\\\\b"
        assert _cef_escape_header("a\nb\rc") == "a\\nb\\rc"

    def test_extension_escapes_backslash_equals_newlines(self):
        assert _cef_escape_extension("a=b") == "a\\=b"
        assert _cef_escape_extension("a\\b") == "a\\\\b"
        assert _cef_escape_extension("a\nb\rc") == "a\\nb\\rc"

    async def _send_and_capture(self, channel: SyslogChannel, event: AlertEvent) -> str:
        sent: list[str] = []
        channel.handler.emit = lambda record: sent.append(record.getMessage())
        ok = await channel.send(event)
        assert ok is True
        assert len(sent) == 1
        return sent[0]

    async def test_agent_id_cannot_inject_extension_fields(self):
        channel = SyslogChannel()
        event = AlertEvent(
            make_request(agent="evil src=forged"),
            make_decision(),
        )
        cef = await self._send_and_capture(channel, event)
        assert "src=evil src\\=forged " in cef
        assert "src=forged " not in cef

    async def test_newlines_are_escaped_in_message(self):
        channel = SyslogChannel()
        event = AlertEvent(
            make_request(agent="evil\nCEF:0|forged"),
            make_decision(reason="line1\nline2"),
        )
        cef = await self._send_and_capture(channel, event)
        assert "\n" not in cef
        assert "\r" not in cef
        assert "line1\\nline2" in cef

    async def test_pipe_in_reason_cannot_break_header(self):
        channel = SyslogChannel()
        event = AlertEvent(
            make_request(),
            make_decision(reason="x|10|src=forged"),
        )
        cef = await self._send_and_capture(channel, event)
        assert "x\\|10\\|src\\=forged" in cef
        # Header still has exactly 7 unescaped pipe separators
        header = cef.split("act=")[0].replace("\\|", "")
        assert header.count("|") == 7


# --- L10: shared HTTP client per channel ---

class TestSharedHttpClient:
    async def test_slack_client_is_reused(self):
        channel = SlackChannel("https://hooks.slack.com/test")
        try:
            c1 = channel._get_client()
            c2 = channel._get_client()
            assert c1 is c2
        finally:
            await channel.close()
        assert channel._client is None

    async def test_webhook_client_is_reused(self):
        channel = WebhookChannel("https://example.com/hook")
        try:
            c1 = channel._get_client()
            c2 = channel._get_client()
            assert c1 is c2
        finally:
            await channel.close()
        assert channel._client is None

    async def test_closed_client_is_recreated(self):
        channel = WebhookChannel("https://example.com/hook")
        c1 = channel._get_client()
        await channel.close()
        c2 = channel._get_client()
        assert c2 is not c1
        await channel.close()


# --- reload_config resource cleanup: AlertEngine.close() ---

class _RecordingCloseChannel(AlertChannel):
    name = "recording-close"

    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class _NoCloseChannel(AlertChannel):
    name = "no-close"


class TestEngineClose:
    def test_close_without_running_loop(self):
        channel = _RecordingCloseChannel()
        engine = AlertEngine(channels=[channel])
        engine.close()
        assert channel.close_calls == 1

    async def test_close_inside_running_loop(self):
        channel = _RecordingCloseChannel()
        engine = AlertEngine(channels=[channel])
        engine.close()
        await asyncio.sleep(0)  # let the scheduled close task run
        assert channel.close_calls == 1

    def test_close_tolerates_channels_without_close(self):
        engine = AlertEngine(channels=[_NoCloseChannel(), _RecordingCloseChannel()])
        engine.close()  # must not raise
        assert engine.channels[1].close_calls == 1

    async def test_real_channel_client_is_closed_and_recreated(self):
        slack = SlackChannel("https://hooks.slack.com/test")
        engine = AlertEngine(channels=[slack])
        slack._get_client()
        assert slack._client is not None
        engine.close()
        await asyncio.sleep(0)
        assert slack._client is None
        # Lazy recreation keeps a reused channel functional
        assert slack._get_client() is not None
        await slack.close()
