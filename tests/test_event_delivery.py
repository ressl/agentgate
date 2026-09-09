"""Transport, receiver, and shutdown boundaries for lifecycle delivery."""

import json
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from examples.event_receiver import MAX_BODY_BYTES, create_app
from mcp_firewall.events import EventDispatcher, EventEmitter, EventWebhook
from mcp_firewall.models import (
    EventEnvelope,
    EventPhase,
    EventsConfig,
    EventWebhookConfig,
    ToolCallRequest,
)


def test_published_schema_matches_model():
    schema = Path(__file__).parents[1] / "docs" / "integration-events.schema.json"
    assert json.loads(schema.read_text()) == EventEnvelope.model_json_schema()


@pytest.mark.parametrize(
    "field,value", [("request_id", True), ("sequence", "1"), ("timestamp", float("inf"))]
)
def test_event_wire_types_are_not_silently_coerced(field, value):
    body = EventEnvelope(event=event()).model_dump(mode="json")
    body["event"][field] = value
    with pytest.raises(ValueError):
        EventEnvelope.model_validate(body)


def test_enabled_event_export_requires_receiver():
    with pytest.raises(ValueError, match="receiver"):
        EventsConfig(enabled=True)


def event():
    return EventEmitter(EventsConfig()).emit(
        ToolCallRequest(tool_name="status"), EventPhase.REQUEST_RECEIVED
    )


@pytest.mark.parametrize(
    "statuses,expected", [([503, 429, 200], 3), ([403], 1), ([302], 1), ([503, 503, 503], 3)]
)
def test_webhook_bounded_retries_and_stable_identity(statuses, expected, monkeypatch):
    received = []
    item = event()

    def receive(request):
        received.append(request)
        return httpx.Response(
            statuses[len(received) - 1], headers={"Location": "https://other.example/"}
        )

    webhook = EventWebhook(EventWebhookConfig(url="https://receiver.example/events"))
    webhook._client = httpx.Client(transport=httpx.MockTransport(receive))
    monkeypatch.setattr("mcp_firewall.events.time.sleep", lambda delay: None)
    try:
        if statuses[-1] == 200:
            webhook(item)
        else:
            with pytest.raises(RuntimeError, match="delivery failed"):
                webhook(item)
    finally:
        webhook.close()
    assert len(received) == expected
    assert {request.headers["Idempotency-Key"] for request in received} == {item.id}
    assert all(
        json.loads(request.content) == EventEnvelope(event=item).model_dump(mode="json")
        for request in received
    )
    assert all(request.url.host == "receiver.example" for request in received)


def test_webhook_transport_errors_do_not_expose_credentials(caplog):
    def fail(request):
        raise httpx.ConnectError("private-url-and-credential", request=request)

    webhook = EventWebhook(EventWebhookConfig(url="https://receiver.example/", max_retries=0))
    webhook._client = httpx.Client(transport=httpx.MockTransport(fail))
    dispatcher = EventDispatcher([webhook])
    dispatcher.publish(event())
    stats = dispatcher.close()
    assert stats.failed == 1
    assert "private-url-and-credential" not in caplog.text


def test_webhook_does_not_read_receiver_response_body():
    class NeverRead(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("Receiver response body must not be read")

    webhook = EventWebhook(EventWebhookConfig(url="https://receiver.example/"))
    webhook._client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=NeverRead()))
    )
    try:
        webhook(event())
    finally:
        webhook.close()


def test_shutdown_deadline_drops_queued_work_and_reports_inflight():
    started, release = threading.Event(), threading.Event()

    def blocked(item):
        started.set()
        release.wait(5)

    dispatcher = EventDispatcher([blocked], capacity=2)
    try:
        dispatcher.publish(event())
        assert started.wait(1)
        dispatcher.publish(event())
        before = time.monotonic()
        stats = dispatcher.close(timeout=0.01)
        assert time.monotonic() - before < 0.5
        assert stats.dropped == 1
        assert stats.in_flight == 1
        assert not dispatcher.publish(event())
    finally:
        release.set()
        dispatcher.close()


def test_receiver_auth_schema_and_deduplication():
    token = "receiver-test-token-" + "x" * 32
    item = event()
    body = EventEnvelope(event=item).model_dump(mode="json")
    headers = {"Authorization": "Bearer " + token, "Idempotency-Key": item.id}
    with TestClient(create_app(token)) as client:
        assert client.post("/events", json=body).status_code == 401
        first = client.post("/events", json=body, headers=headers)
        assert first.status_code == 200
        assert first.json()["duplicate"] is False
        assert client.post("/events", json=body, headers=headers).json()["duplicate"] is True
        body["event"]["schema_version"] = 2
        assert client.post("/events", json=body, headers=headers).status_code == 400
        assert (
            client.post("/events", content=b"x" * (MAX_BODY_BYTES + 1), headers=headers).status_code
            == 413
        )


def test_receiver_rejects_unknown_fields_mismatched_id_and_sensitive_input():
    token = "receiver-test-token-" + "x" * 32
    body = EventEnvelope(event=event()).model_dump(mode="json")
    with TestClient(create_app(token)) as client:
        headers = {"Authorization": "Bearer " + token}
        assert client.post("/events", json=body, headers=headers).status_code == 400
        body["event"]["arguments"] = {"password": "do-not-echo"}
        reply = client.post("/events", json=body, headers=headers)
        assert reply.status_code == 400
        assert "do-not-echo" not in reply.text
