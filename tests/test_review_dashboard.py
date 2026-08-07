"""Tests for the dashboard code-review fixes (H7, H8, M6, M11, L15)."""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
import time

import pytest
from starlette.testclient import TestClient

from mcp_firewall.dashboard import app as app_module
from mcp_firewall.dashboard.app import DashboardState, app, state
from mcp_firewall.dashboard.server import start_dashboard


# --- M11: /api/events limit validation ---

class TestEventsLimit:
    def test_limit_zero_rejected(self):
        client = TestClient(app)
        resp = client.get("/api/events", params={"limit": 0})
        assert resp.status_code == 422

    def test_negative_limit_rejected(self):
        client = TestClient(app)
        resp = client.get("/api/events", params={"limit": -5})
        assert resp.status_code == 422

    def test_valid_limit_accepted(self):
        client = TestClient(app)
        resp = client.get("/api/events", params={"limit": 5})
        assert resp.status_code == 200
        assert len(resp.json()) <= 5

    def test_replay_events_are_tagged(self):
        # Replayed events must carry replay=True so the client does not
        # count them against the (server-side) stats a second time.
        with state._lock:
            saved_events, state.events = state.events, []
            saved_stats, state.stats = state.stats, {k: 0 for k in state.stats}
        try:
            state.add_event({"action": "deny", "tool": "exec"})
            client = TestClient(app)
            resp = client.get("/api/events", params={"limit": 10})
            assert resp.status_code == 200
            events = resp.json()
            assert len(events) == 1
            assert events[0]["replay"] is True
        finally:
            with state._lock:
                state.events = saved_events
                state.stats = saved_stats


# --- H7: broadcast scheduled on the dashboard server's loop ---

class _FakeWS:
    def __init__(self) -> None:
        self.received: list[dict] = []

    async def send_json(self, event: dict) -> None:
        self.received.append(event)


class TestCrossThreadBroadcast:
    def test_add_event_from_other_thread_reaches_websocket(self):
        s = DashboardState()
        ws = _FakeWS()
        loop = asyncio.new_event_loop()
        ready = threading.Event()

        def run_loop() -> None:
            asyncio.set_event_loop(loop)
            s.set_loop(loop)
            with s._lock:
                s._websockets.append(ws)
            ready.set()
            loop.run_forever()

        thread = threading.Thread(target=run_loop, daemon=True)
        thread.start()
        try:
            assert ready.wait(5)
            # Called from a thread with no running loop — the broadcast must
            # still be scheduled on the registered (uvicorn) loop.
            s.add_event({"action": "deny", "tool": "exec"})
            deadline = time.time() + 5
            while not ws.received and time.time() < deadline:
                time.sleep(0.05)
            assert ws.received and ws.received[0]["tool"] == "exec"
        finally:
            s.set_loop(None)
            loop.call_soon_threadsafe(loop.stop)
            thread.join(5)
            loop.close()

    def test_add_event_without_loop_does_not_raise(self):
        s = DashboardState()
        s.add_event({"action": "allow", "tool": "read_file"})
        assert s.stats["total"] == 1

    async def test_add_event_inside_running_loop_still_broadcasts(self):
        # Fallback when no server loop is registered (e.g. tests).
        s = DashboardState()
        ws = _FakeWS()
        with s._lock:
            s._websockets.append(ws)
        s.add_event({"action": "allow", "tool": "read_file"})
        await asyncio.sleep(0.05)
        assert ws.received and ws.received[0]["tool"] == "read_file"

    def test_dead_websocket_removed(self):
        s = DashboardState()

        class DeadWS:
            async def send_json(self, event: dict) -> None:
                raise ConnectionError("gone")

        async def run() -> None:
            with s._lock:
                s._websockets.append(DeadWS())
            s.add_event({"action": "allow", "tool": "x"})
            await asyncio.sleep(0.05)

        asyncio.run(run())
        with s._lock:
            assert s._websockets == []


# --- M6: bounded aggregation dicts ---

class TestBoundedAggregation:
    def test_by_tool_capped(self, monkeypatch):
        monkeypatch.setattr(app_module, "MAX_AGG_KEYS", 10)
        s = DashboardState()
        for i in range(50):
            s.add_event({"action": "allow", "tool": f"tool-{i}"})
        assert len(s.by_tool) <= 11  # 10 distinct keys + "other"
        assert s.by_tool["other"] == 40
        assert sum(s.by_tool.values()) == 50

    def test_by_agent_capped(self, monkeypatch):
        monkeypatch.setattr(app_module, "MAX_AGG_KEYS", 10)
        s = DashboardState()
        for i in range(25):
            s.add_event({"action": "allow", "tool": "t", "agent": f"agent-{i}"})
        assert len(s.by_agent) <= 11
        assert sum(s.by_agent.values()) == 25


# --- L15: port already in use ---

class TestServerStartupFailure:
    def test_port_in_use_logs_error_and_thread_exits(self, caplog):
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        try:
            with caplog.at_level(logging.ERROR, logger="mcp_firewall.dashboard"):
                thread = start_dashboard(port=port)
                thread.join(timeout=15)
            assert not thread.is_alive()
            assert any(
                "Dashboard server failed" in record.message
                for record in caplog.records
            )
        finally:
            blocker.close()
            state.set_loop(None)


# --- H8: dashboard HTML must not interpolate event data via innerHTML ---

class TestNoStoredXss:
    def test_no_innerhtml_interpolation(self):
        assert ".innerHTML" not in app_module.DASHBOARD_HTML
        assert "textContent" in app_module.DASHBOARD_HTML
