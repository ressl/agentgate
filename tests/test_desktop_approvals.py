"""Approval bindings, lifecycle and policy composition."""

import asyncio

import pytest

from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.models import Action, GatewayConfig, RuleConfig, ToolCallRequest
from mcp_firewall.sdk import Gateway


async def pending(broker):
    for _ in range(100):
        items = broker.pending()
        if items:
            return items[0]
        await asyncio.sleep(0.005)
    pytest.fail("No pending approval")


async def test_single_use_approval_bound_to_original_arguments():
    broker = ApprovalBroker()
    broker.pending()
    request = ToolCallRequest(tool_name="status", arguments={"scope": "local"})
    task = asyncio.create_task(broker.arequest(request, "session"))
    item = await pending(broker)
    with pytest.raises(ValueError, match="binding"):
        broker.decide(item.id, "wrong-binding", True)
    broker.decide(item.id, item.request_hash, True)
    with pytest.raises(LookupError):
        broker.decide(item.id, item.request_hash, True)
    assert (await task).approved


async def test_changed_arguments_cannot_be_approved():
    broker = ApprovalBroker()
    broker.pending()
    request = ToolCallRequest(tool_name="write", arguments={"path": "/workspace/example"})
    task = asyncio.create_task(broker.arequest(request, "session"))
    item = await pending(broker)
    request.arguments["path"] = "/workspace/different"
    with pytest.raises(ValueError, match="changed"):
        broker.decide(item.id, item.request_hash, True)
    assert not (await task).approved


@pytest.mark.parametrize("reason", ["timeout", "disconnect", "lease", "cancel", "close"])
async def test_interrupted_approval_fails_closed(reason):
    broker = ApprovalBroker(timeout_seconds=0.15, controller_timeout=0.06)
    broker.pending()
    task = asyncio.create_task(broker.arequest(ToolCallRequest(tool_name="status"), "session"))
    item = await pending(broker)
    if reason == "disconnect":
        broker.disconnect()
    elif reason == "close":
        broker.close()
    elif reason == "cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert broker.pending() == []
        return
    elif reason == "timeout":
        for _ in range(10):
            await asyncio.sleep(0.02)
            broker.pending()
    result = await asyncio.wait_for(task, 1)
    assert not result.approved
    assert broker.pending() == []
    with pytest.raises(LookupError):
        broker.decide(item.id, item.request_hash, True)


async def test_no_controller_and_full_queue_deny_without_waiting():
    broker = ApprovalBroker(max_pending=1)
    assert not (await broker.arequest(ToolCallRequest(tool_name="status"), "one")).approved
    broker.pending()
    first = asyncio.create_task(broker.arequest(ToolCallRequest(tool_name="status"), "one"))
    await pending(broker)
    second = await broker.arequest(ToolCallRequest(tool_name="status"), "two")
    assert not second.approved
    broker.disconnect()
    assert not (await first).approved


async def test_preview_redacts_sensitive_keys_and_values():
    broker = ApprovalBroker()
    broker.pending()
    request = ToolCallRequest(
        tool_name="status",
        arguments={
            "password": "not-a-recognizable-secret",
            "nested": {"token": "short-secret"},
            "text": "AKIAIOSFODNN7EXAMPLE alice@example.com",
        },
    )
    task = asyncio.create_task(broker.arequest(request, "session"))
    item = await pending(broker)
    rendered = item.model_dump_json()
    for sensitive in [
        "not-a-recognizable-secret",
        "short-secret",
        "AKIAIOSFODNN7EXAMPLE",
        "alice@example.com",
    ]:
        assert sensitive not in rendered
    assert item.redacted
    broker.disconnect()
    await task


async def test_oversized_preview_is_not_approvable():
    broker = ApprovalBroker()
    broker.pending()
    result = await broker.arequest(
        ToolCallRequest(tool_name="status", arguments={"command": "x" * 20000}), "s"
    )
    assert not result.approved
    assert broker.pending() == []


async def test_global_denial_and_chain_checks_remain_authoritative():
    broker = ApprovalBroker()
    broker.pending()
    config = GatewayConfig(default_action=Action.PROMPT)
    config.audit.enabled = False
    config.rules = [RuleConfig(name="deny-danger", tool="danger", action=Action.DENY)]
    async with Gateway(config=config, approval_broker=broker) as gateway:
        assert (await gateway.acheck("danger")).blocked
        assert broker.pending() == []
        for tool in ["read_file", "http_post"]:
            task = asyncio.create_task(gateway.acheck(tool))
            item = await pending(broker)
            broker.decide(item.id, item.request_hash, True)
            result = await task
            assert result.blocked == (tool == "http_post")


async def test_sdk_close_cancels_pending_approval_before_waiting_for_state_lock():
    broker = ApprovalBroker()
    broker.pending()
    config = GatewayConfig()
    config.audit.enabled = False
    gateway = Gateway(config=config, approval_broker=broker)
    task = asyncio.create_task(gateway.acheck("status"))
    await pending(broker)
    await asyncio.wait_for(gateway.aclose(), 1)
    assert (await task).blocked
    assert broker.pending() == []


def test_auto_approval_and_external_broker_are_incompatible():
    with pytest.raises(ValueError, match="auto"):
        Gateway(approval_broker=ApprovalBroker(), auto_approve=True)


async def test_cancelling_sdk_check_removes_only_its_approval():
    broker = ApprovalBroker()
    broker.pending()
    config = GatewayConfig()
    config.audit.enabled = False
    async with Gateway(config=config, approval_broker=broker) as gateway:
        task = asyncio.create_task(gateway.acheck("status"))
        item = await pending(broker)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        with pytest.raises(LookupError):
            broker.decide(item.id, item.request_hash, True)
        next_call = asyncio.create_task(gateway.acheck("status"))
        next_item = await pending(broker)
        broker.decide(next_item.id, next_item.request_hash, True)
        assert not (await next_call).blocked


async def test_reconnection_cannot_resurrect_expired_request(monkeypatch):
    import mcp_firewall.approvals as approvals

    now = [100.0]
    monkeypatch.setattr(approvals.time, "monotonic", lambda: now[0])
    broker = ApprovalBroker()
    broker.pending()
    # Synchronous registration prevents a worker timer from hiding a late-expiry bug.
    item = broker._create(ToolCallRequest(tool_name="status"), "session", ())
    now[0] += 11
    assert broker.pending() == []
    with pytest.raises(LookupError):
        broker.decide(item.view.id, item.view.request_hash, True)
    assert not broker._wait(item).approved


async def test_preview_key_collisions_cannot_hide_arguments():
    broker = ApprovalBroker()
    broker.pending()
    task = asyncio.create_task(
        broker.arequest(
            ToolCallRequest(
                tool_name="status",
                arguments={"alice@example.com": "one", "bob@example.com": "two"},
            ),
            "s",
        )
    )
    await asyncio.sleep(0.01)
    try:
        assert broker.pending() == []
    finally:
        broker.disconnect()
        assert not (await task).approved


def test_mutation_after_decision_but_before_return_still_denies():
    broker = ApprovalBroker()
    broker.pending()
    request = ToolCallRequest(tool_name="status")
    item = broker._create(request, "session", ())
    broker.decide(item.view.id, item.view.request_hash, True)
    request.tool_name = "changed"
    assert not broker._wait(item).approved
