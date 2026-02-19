"""Tests for Phase 3: Dashboard + Alerting."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from mcp_firewall.alerts.engine import AlertEngine, AlertEvent
from mcp_firewall.alerts.webhook import WebhookChannel
from mcp_firewall.alerts.slack import SlackChannel
from mcp_firewall.dashboard.app import DashboardState, app, state
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


# --- Alert Engine ---

class TestAlertEngine:
    def test_records_deny_events(self):
        engine = AlertEngine(min_severity=Severity.LOW)
        engine.process(make_request(), make_decision())
        assert len(engine.history) == 1

    def test_ignores_allow_events(self):
        engine = AlertEngine(min_severity=Severity.LOW)
        engine.process(make_request(), make_decision(action=Action.ALLOW))
        assert len(engine.history) == 0

    def test_severity_threshold(self):
        engine = AlertEngine(min_severity=Severity.CRITICAL)
        engine.process(make_request(), make_decision(severity=Severity.HIGH))
        assert len(engine.history) == 0
        engine.process(make_request(), make_decision(severity=Severity.CRITICAL))
        assert len(engine.history) == 1

    def test_history_trimming(self):
        engine = AlertEngine(min_severity=Severity.LOW)
        for _ in range(10001):
            engine.process(make_request(), make_decision())
        assert len(engine.history) <= 5001


class TestAlertEvent:
    def test_to_dict(self):
        req = make_request(tool="shell_exec", agent="claude")
        dec = make_decision(severity=Severity.CRITICAL, reason="injection detected")
        event = AlertEvent(req, dec)

        d = event.to_dict()
        assert d["severity"] == "critical"
        assert d["tool"] == "shell_exec"
        assert d["agent"] == "claude"
        assert d["action"] == "deny"
        assert d["reason"] == "injection detected"

    def test_title(self):
        event = AlertEvent(make_request(), make_decision())
        assert "HIGH" in event.title
        assert "injection" in event.title

    def test_message(self):
        event = AlertEvent(make_request(tool="exec"), make_decision())
        assert "exec" in event.message


# --- Dashboard State ---

class TestDashboardState:
    def test_add_event(self):
        s = DashboardState()
        s.add_event({"action": "deny", "tool": "exec", "severity": "high", "agent": "test"})
        assert s.stats["total"] == 1
        assert s.stats["denied"] == 1

    def test_stats_tracking(self):
        s = DashboardState()
        s.add_event({"action": "allow", "tool": "read_file"})
        s.add_event({"action": "deny", "tool": "exec"})
        s.add_event({"action": "redact", "tool": "search"})
        assert s.stats["total"] == 3
        assert s.stats["allowed"] == 1
        assert s.stats["denied"] == 1
        assert s.stats["redacted"] == 1

    def test_by_tool_tracking(self):
        s = DashboardState()
        s.add_event({"action": "allow", "tool": "read_file"})
        s.add_event({"action": "allow", "tool": "read_file"})
        s.add_event({"action": "deny", "tool": "exec"})
        assert s.by_tool["read_file"] == 2
        assert s.by_tool["exec"] == 1

    def test_event_buffer_limit(self):
        s = DashboardState()
        for i in range(6000):
            s.add_event({"action": "allow", "tool": f"t{i}"})
        assert len(s.events) <= 3500


# --- Dashboard API ---

class TestDashboardAPI:
    def test_index(self):
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "mcp-firewall" in resp.text

    def test_stats_endpoint(self):
        client = TestClient(app)
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "stats" in data
        assert "by_severity" in data
        assert "uptime" in data

    def test_events_endpoint(self):
        client = TestClient(app)
        resp = client.get("/api/events?limit=10")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_websocket(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            # Should connect without error
            pass  # Auto-closes
