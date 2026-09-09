"""Behavioral coverage for the public integration contract."""

import asyncio
import json
import threading
import time

import pytest

from mcp_firewall.events import EventDispatcher, EventEmitter
from mcp_firewall.models import (
    Action,
    EventPhase,
    EventsConfig,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    ToolCallRequest,
    ToolCallResponse,
)
from mcp_firewall.sdk import Gateway


def config():
    cfg = GatewayConfig(default_action=Action.ALLOW)
    cfg.audit.enabled = False
    return cfg


def test_safe_sdk_defaults_and_explicit_auto_approval():
    cfg = config()
    cfg.default_action = Action.PROMPT
    with Gateway(config=cfg) as gateway:
        assert gateway.check("status").blocked
    with Gateway(config=cfg, auto_approve=True) as gateway:
        assert gateway.check("status").allowed


def test_config_file_audit_is_preserved_and_correlated(tmp_path):
    path = tmp_path / "audit.jsonl"
    settings = tmp_path / "gateway.yaml"
    settings.write_text(f"defaultAction: allow\naudit:\n  path: {path}\n")
    events = []
    with Gateway(config_path=settings, event_handler=events.append) as gateway:
        result = gateway.check("status")
        gateway.scan_response("OK", context=result.context)
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    assert entries[0]["event"]["call_id"] == result.context.call_id
    assert {event.call_id for event in events} == {result.context.call_id}
    assert [event.phase for event in events] == [
        EventPhase.REQUEST_RECEIVED,
        EventPhase.POLICY_DECISION,
        EventPhase.REQUEST_ALLOWED,
        EventPhase.RESPONSE_RECEIVED,
        EventPhase.RESPONSE_ALLOWED,
    ]


async def test_async_parallel_calls_keep_context_and_structured_protection():
    events = []
    async with Gateway(config=config(), event_handler=events.append) as gateway:
        checks = await asyncio.gather(*(gateway.acheck("status") for _ in range(20)))
        for result in reversed(checks):
            response = ToolCallResponse(
                request_id="ignored", structured_content={"key": "AKIAIOSFODNN7EXAMPLE"}
            )
            scanned = await gateway.ascan_tool_response(response, context=result.context)
            assert "AKIAIOSFODNN7EXAMPLE" not in scanned.response.model_dump_json()
            assert scanned.modified
    assert len({r.context.call_id for r in checks}) == 20
    for result in checks:
        phases = [event.phase for event in events if event.call_id == result.context.call_id]
        assert phases[0] == EventPhase.REQUEST_RECEIVED
        assert phases[-1] == EventPhase.RESPONSE_REDACTED
        assert EventPhase.REQUEST_FORWARDED not in phases  # SDK does not execute tools
    assert [event.sequence for event in events] == list(range(1, len(events) + 1))


def test_export_redaction_is_independent_of_scanner_configuration():
    seen = []
    emitter = EventEmitter(EventsConfig(), handler=seen.append)
    request = ToolCallRequest(tool_name="AKIAIOSFODNN7EXAMPLE", agent_id="alice@example.com")
    decision = PipelineDecision(
        stage=PipelineStage.POLICY,
        action=Action.DENY,
        reason="password=hunter42 AKIAIOSFODNN7EXAMPLE alice@example.com",
        details={"raw": "DO-NOT-EXPORT"},
    )
    emitter.emit(request, EventPhase.REQUEST_DENIED, decision)
    emitter.close()
    text = seen[0].model_dump_json()
    for sensitive in ["hunter42", "AKIAIOSFODNN7EXAMPLE", "alice@example.com", "DO-NOT-EXPORT"]:
        assert sensitive not in text


def test_slow_observer_has_bounded_queue_and_does_not_block_publish():
    started, release = threading.Event(), threading.Event()

    def blocked(event):
        started.set()
        release.wait(5)

    dispatcher = EventDispatcher([blocked], capacity=1)
    event = EventEmitter(EventsConfig()).emit(
        ToolCallRequest(tool_name="status"), EventPhase.REQUEST_RECEIVED
    )
    try:
        assert dispatcher.publish(event)
        assert started.wait(1)
        assert dispatcher.publish(event)
        assert not dispatcher.publish(event)
        assert dispatcher.stats.dropped == 1
    finally:
        release.set()
        dispatcher.close()
    assert dispatcher.stats.delivered == 2


def test_failed_observer_never_changes_protection(caplog):
    def broken(event):
        raise RuntimeError("secret-from-observer")

    cfg = config()
    cfg.default_action = Action.DENY
    with Gateway(config=cfg, event_handler=broken) as gateway:
        assert gateway.check("status").blocked
    assert gateway.delivery_stats.failed > 0
    assert "secret-from-observer" not in caplog.text


def test_context_cannot_be_used_with_a_different_gateway():
    with Gateway(config=config()) as first, Gateway(config=config()) as second:
        result = first.check("status")
        with pytest.raises(ValueError, match="session"):
            second.scan_response("OK", context=result.context)


async def test_async_check_does_not_block_loop_and_cancellation_never_means_execution(monkeypatch):
    started, release = threading.Event(), threading.Event()
    events = []
    gateway = Gateway(config=config(), event_handler=events.append)
    evaluate = gateway._pipeline._evaluate_inbound

    def slow(request, **kwargs):
        started.set()
        release.wait(5)
        return evaluate(request, **kwargs)

    monkeypatch.setattr(gateway._pipeline, "_evaluate_inbound", slow)
    task = asyncio.create_task(gateway.acheck("status"))
    try:
        assert await asyncio.to_thread(started.wait, 1)
        await asyncio.wait_for(asyncio.sleep(0), timeout=0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await gateway.aclose()
    assert EventPhase.REQUEST_FORWARDED not in [event.phase for event in events]


def test_unmatched_scan_and_tool_error_do_not_claim_successful_execution():
    events = []
    with Gateway(config=config(), event_handler=events.append) as gateway:
        gateway.scan_tool_response(ToolCallResponse(request_id="external", is_error=True))
    assert all(not event.correlated for event in events)
    assert events[-1].phase == EventPhase.RESPONSE_ALLOWED
    assert events[-1].response_is_error is True


def test_signed_audit_embeds_the_same_sanitized_event(tmp_path, monkeypatch):
    from mcp_firewall.audit.logger import AuditLogger

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "keys"))
    cfg = config()
    cfg.audit.enabled = True
    cfg.audit.sign = True
    cfg.audit.path = str(tmp_path / "audit.jsonl")
    events = []
    with Gateway(config=cfg, event_handler=events.append) as gateway:
        gateway.check("status", {"password": "do-not-export"}, agent="alice@example.com")
    entry = json.loads((tmp_path / "audit.jsonl").read_text())
    policy_event = next(event for event in events if event.phase == EventPhase.POLICY_DECISION)
    assert entry["event"] == policy_event.model_dump(mode="json")
    assert "alice@example.com" not in json.dumps(entry)
    assert "do-not-export" not in json.dumps(entry)
    assert AuditLogger(cfg, verification_only=True).verify_chain()[0]


def test_busy_event_reload_preserves_previous_configuration(tmp_path):
    started, release = threading.Event(), threading.Event()

    def blocked(event):
        started.set()
        release.wait(5)

    cfg = config()
    gateway = Gateway(config=cfg, event_handler=blocked)
    replacement = tmp_path / "config.yaml"
    replacement.write_text(
        "defaultAction: deny\nevents:\n  queueSize: 1\naudit:\n  enabled: false\n"
    )
    try:
        result = gateway.check("status")
        assert started.wait(1)
        with pytest.raises(ValueError, match="busy"):
            gateway.reload(replacement)
        assert gateway.config.default_action == Action.ALLOW
        assert gateway.config.events.queue_size == cfg.events.queue_size
        assert gateway._pipeline.events.session_id == result.context.session_id
    finally:
        release.set()
        gateway.close()


def test_reload_keeps_handler_session_context_and_delivery_counts(tmp_path):
    events = []
    settings = tmp_path / "config.yaml"
    settings.write_text("defaultAction: allow\nevents:\n  queueSize: 2\naudit:\n  enabled: false\n")
    with Gateway(config=config(), event_handler=events.append) as gateway:
        result = gateway.check("status")
        deadline = time.monotonic() + 2
        while gateway.delivery_stats.delivered != 3 and time.monotonic() < deadline:
            threading.Event().wait(0.005)
        assert gateway.delivery_stats.delivered == 3
        gateway.reload(settings)
        gateway.scan_response("OK", context=result.context)
    assert gateway.delivery_stats.delivered == 5
    assert {event.session_id for event in events} == {result.context.session_id}
    assert {event.call_id for event in events} == {result.context.call_id}


def test_event_fields_are_bounded_before_export():
    emitter = EventEmitter(EventsConfig())
    event = emitter.emit(
        ToolCallRequest(tool_name="x" * 100000, protocol_id="y" * 100000),
        EventPhase.REQUEST_RECEIVED,
    )
    assert len(event.model_dump_json()) < 2000
    assert "OMITTED" in event.tool


def test_deep_structured_response_is_blocked_without_mutating_input():
    nested = {}
    node = nested
    for _ in range(1200):
        node["child"] = {}
        node = node["child"]
    node["secret"] = "AKIAIOSFODNN7EXAMPLE"
    events = []
    with Gateway(config=config(), event_handler=events.append) as gateway:
        result = gateway.scan_tool_response(
            ToolCallResponse(request_id="", structured_content=nested)
        )
    assert result.blocked
    assert result.response.structured_content is None
    assert events[-1].phase == EventPhase.RESPONSE_DENIED
    assert node["secret"] == "AKIAIOSFODNN7EXAMPLE"


def test_legacy_alerts_scrub_metadata_and_do_not_retain_raw_arguments():
    from mcp_firewall.alerts.engine import AlertEvent

    alert = AlertEvent(
        ToolCallRequest(tool_name="AKIAIOSFODNN7EXAMPLE", arguments={"password": "raw-input"}),
        PipelineDecision(
            stage=PipelineStage.POLICY, action=Action.DENY, reason="alice@example.com"
        ),
    )
    assert alert.request.arguments == {}
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(alert.to_dict())
    assert "alice@example.com" not in json.dumps(alert.to_dict())


def test_sdk_close_rejects_further_work():
    gateway = Gateway(config=config())
    gateway.close()
    with pytest.raises(RuntimeError, match="closed"):
        gateway.check("status")
    with pytest.raises(RuntimeError, match="closed"):
        gateway.scan_response("OK")
