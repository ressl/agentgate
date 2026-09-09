"""Authenticated replay for native integrations, independent of approval leases."""

import httpx
import pytest

from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.dashboard.app import app, state
from mcp_firewall.dashboard.approvals import configure_approvals
from mcp_firewall.dashboard.event_feed import IntegrationEventFeed
from mcp_firewall.models import EventPhase, SecurityEvent, ToolCallRequest


def event(sequence):
    return SecurityEvent(
        session_id="00000000-0000-4000-8000-000000000001",
        call_id="00000000-0000-4000-8000-000000000002",
        sequence=sequence,
        phase=EventPhase.REQUEST_RECEIVED,
        tool="status",
        agent="test",
    )


def test_feed_paginates_and_reports_retention_loss_and_restarts():
    feed = IntegrationEventFeed(capacity=3)
    feed.reset(enabled=True)
    for sequence in range(1, 5):
        feed.record(event(sequence))
    page = feed.read(after=0, limit=2)
    assert page.gap
    assert page.oldest_cursor == 2
    assert page.cursor == 3
    assert [item.sequence for item in page.events] == [2, 3]
    assert page.has_more
    second = feed.read(after=page.cursor, stream_id=page.stream_id)
    assert not second.gap
    assert not second.has_more
    assert [item.sequence for item in second.events] == [4]
    assert feed.read(after=second.cursor).events == []
    with pytest.raises(ValueError):
        feed.read(after=100)
    feed.reset(enabled=True)
    with pytest.raises(LookupError):
        feed.read(after=second.cursor, stream_id=second.stream_id)


async def test_feed_requires_authentication_and_does_not_connect_controller():
    broker = ApprovalBroker()
    token = "synthetic-native-feed-" * 3
    configure_approvals(broker, token)
    try:
        state.add_security_event(event(1))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:9090"
        ) as client:
            assert (await client.get("/api/integration-events")).status_code == 401
            headers = {"Authorization": f"Bearer {token}"}
            response = await client.get("/api/integration-events", headers=headers)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert [item["phase"] for item in response.json()["events"]] == ["request_received"]
            assert "arguments" not in response.text
            assert not (await broker.arequest(ToolCallRequest(tool_name="status"), "s")).approved
            headers["Origin"] = "https://foreign.example"
            assert (await client.get("/api/integration-events", headers=headers)).status_code == 403
    finally:
        configure_approvals(None, None)
        broker.close()


def test_disabled_feed_does_not_collect_events():
    feed = IntegrationEventFeed()
    feed.record(event(1))
    assert feed.read().events == []
