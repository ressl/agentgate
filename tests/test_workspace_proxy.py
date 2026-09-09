"""Capture only admitted, correlated calls and seal even blocked/error responses."""

import json

import pytest

from mcp_firewall.models import Action, GatewayConfig
from mcp_firewall.proxy.stdio import StdioProxy
from mcp_firewall.workspace import WorkspaceSnapshots


@pytest.fixture
def proxy(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "file").write_text("before")
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.enabled = False
    manager = WorkspaceSnapshots(root)
    proxy = StdioProxy(config, snapshots=manager)
    errors = []
    proxy._send_error = lambda *args: errors.append(args)
    try:
        yield proxy, root, manager, errors
    finally:
        proxy._finish_pending()
        proxy.pipeline.close()


def call(request_id=1):
    value = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "edit", "arguments": {}}}
    if request_id is not None:
        value["id"] = request_id
    return json.dumps(value).encode()


async def test_capture_before_forward_and_seal_after_error(proxy):
    proxy, root, manager, errors = proxy
    assert await proxy._intercept_request(call()) == call()
    assert manager.view().busy
    assert manager.view().snapshots[0].files == []
    (root / "file").write_text("server-side effect")
    response = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "failed"}}
    ).encode()
    assert await proxy._intercept_response(response) == response
    snapshot = manager.view().snapshots[0]
    assert snapshot.state == "complete" and snapshot.file_count == 1
    assert not manager.view().busy
    preview = manager.preview(snapshot.id, snapshot.files[0].id)
    assert "-before" in preview.diff and "+server-side effect" in preview.diff
    manager.restore(snapshot.id, snapshot.files[0].id, preview.revision)
    assert (root / "file").read_text() == "before"
    assert not errors


async def test_refuse_overlap_notifications_and_capacity_before_forward(proxy):
    proxy, _, manager, errors = proxy
    assert await proxy._intercept_request(call(None)) is None
    assert not manager.view().snapshots and not errors
    assert await proxy._intercept_request(call(1)) is not None
    assert await proxy._intercept_request(call(2)) is None
    assert len(manager.view().snapshots) == 1
    assert "in flight" in errors[-1][-1]
    proxy._finish_pending()
    assert manager.view().snapshots[0].state == "incomplete"
    for number in range(3, 10):
        assert await proxy._intercept_request(call(number)) is not None
        await proxy._intercept_response(
            json.dumps({"id": number, "result": {"content": []}}).encode()
        )
    assert await proxy._intercept_request(call(10)) is None
    assert "capacity" in errors[-1][-1]


async def test_denied_request_and_capture_failure_never_forward(proxy):
    proxy, root, manager, errors = proxy
    proxy.pipeline.config.default_action = Action.DENY
    assert await proxy._intercept_request(call(1)) is None
    assert manager.view().snapshots == []
    proxy.pipeline.config.default_action = Action.ALLOW
    (root / "unsafe").symlink_to(root.parent)
    assert await proxy._intercept_request(call(2)) is None
    assert manager.view().snapshots == []
    assert len(errors) == 2


async def test_invalid_or_uncorrelated_response_cannot_finish_active_capture(proxy):
    proxy, _, manager, _ = proxy
    await proxy._intercept_request(call(1))
    assert await proxy._intercept_response(b"not json") is None
    await proxy._intercept_response(b'{"id":99,"result":{"content":[]}}')
    assert manager.view().busy
    proxy._finish_pending()
    assert manager.view().snapshots[0].state == "incomplete"


async def test_outbound_redaction_does_not_hide_filesystem_effects(proxy):
    proxy, root, manager, _ = proxy
    await proxy._intercept_request(call(1))
    (root / "file").write_text("tool changed workspace")
    response = await proxy._intercept_response(
        json.dumps(
            {"id": 1, "result": {"content": [{"type": "text", "text": "AKIAIOSFODNN7EXAMPLE"}]}}
        ).encode()
    )
    assert b"AKIAIOSFODNN7EXAMPLE" not in response
    assert manager.view().snapshots[0].file_count == 1


async def test_snapshot_denial_is_recorded_in_audit(proxy):
    from mcp_firewall.audit.logger import AuditLogger

    proxy, root, _, _ = proxy
    config = GatewayConfig(default_action=Action.ALLOW)
    config.audit.path = str(root.parent / "audit.jsonl")
    proxy.pipeline.audit = AuditLogger(config)
    (root / "unsafe").symlink_to(root.parent)
    assert await proxy._intercept_request(call(1)) is None
    entries = [json.loads(line) for line in (root.parent / "audit.jsonl").read_text().splitlines()]
    assert entries[-1]["decision"] == "deny"
    assert entries[-1]["stage"] == "policy"
    assert entries[-1]["reason"].startswith("Workspace snapshot admission:")
    assert entries[-1]["event"]["phase"] == "policy_decision"
    assert "unsafe" not in entries[-1]["reason"]
