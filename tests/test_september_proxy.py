"""Protocol-level regressions for findings 1, 5, 12 and 13."""

import asyncio
import io
import json
import os
import sys

import pytest
from rich.console import Console

from mcp_firewall.dashboard.app import DashboardState
from mcp_firewall.models import Action, GatewayConfig
from mcp_firewall.proxy.stdio import StdioProxy

SECRET = "AKIA" + "Z" * 16


def proxy():
    return StdioProxy(
        GatewayConfig(default_action=Action.ALLOW, audit={"enabled": False}),
        Console(file=io.StringIO()),
    )


def call(request_id=1, tool="status"):
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool}}
    ).encode()


@pytest.mark.parametrize("action", [Action.REDACT, Action.DENY])
@pytest.mark.parametrize("location", ["structuredContent", "resource", "_meta"])
async def test_every_secret_copy_is_removed(action, location):
    p = proxy()
    p.config.secrets.action = action
    result = {"content": [{"type": "text", "text": SECRET}]}
    if location == "resource":
        result["content"].append(
            {"type": "resource", "resource": {"uri": "file:///x", "text": SECRET}}
        )
    else:
        result[location] = {"copy": SECRET}
    raw = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()
    output = await p._intercept_response(raw)
    assert SECRET.encode() not in output
    if action == Action.DENY:
        assert set(json.loads(output)["result"]) == {"content", "isError"}


@pytest.mark.parametrize(
    "content",
    [
        None,
        "bad",
        [1],
        [{"type": "text", "text": 123}],
        [{"type": "resource", "resource": {"text": 123}}],
    ],
)
async def test_malformed_content_returns_safe_error_and_next_call_works(content):
    p = proxy()
    await p._intercept_request(call())
    out = await p._intercept_response(
        json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": content}}).encode()
    )
    assert json.loads(out)["error"]["code"] == -32603
    assert await p._intercept_request(call(2)) is not None
    assert not p._pending_requests.get((int, 1))


@pytest.mark.parametrize("raw", [b"\xff", b"not json", b"null", b"[]"])
async def test_bad_wire_data_is_dropped(raw):
    p = proxy()
    assert await p._intercept_request(raw) is None
    assert await p._intercept_response(raw) is None


async def test_dashboard_outbound_events_keep_identity_without_double_counting(monkeypatch):
    state = DashboardState()
    monkeypatch.setattr("mcp_firewall.proxy.stdio.dashboard_state", state)
    p = proxy()
    p._agent_id = "review-agent"
    await p._intercept_request(call(1, "one"))
    await p._intercept_request(call("1", "two"))
    # Replies arrive in the opposite order; int and string IDs remain distinct.
    for request_id in ["1", 1]:
        await p._intercept_response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": SECRET}]},
                }
            ).encode()
        )
    assert state.stats["total"] == 2
    assert state.stats["allowed"] == 2
    assert state.stats["redacted"] == 2
    assert [e["tool"] for e in state.events if e.get("direction") == "outbound"] == ["two", "one"]
    assert all(e["agent"] == "review-agent" for e in state.events)
    assert not p._pending_requests


async def test_pending_requests_are_bounded_and_duplicates_rejected(monkeypatch):
    monkeypatch.setattr("mcp_firewall.proxy.stdio.MAX_PENDING_REQUESTS", 1)
    p = proxy()
    assert await p._intercept_request(call(1)) is not None
    assert await p._intercept_request(call(1)) is None
    assert await p._intercept_request(call(2)) is None
    await p._intercept_response(
        b'{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"test"}}'
    )
    assert await p._intercept_request(call(2)) is not None


async def start_cli(tmp_path, server):
    c = tmp_path / "config.yaml"
    c.write_text("defaultAction: allow\naudit:\n  enabled: false\n")
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_firewall",
        "wrap",
        "--config",
        str(c),
        "--",
        sys.executable,
        "-c",
        server,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def finish(p):
    if p.returncode is None:
        p.terminate()
    await asyncio.wait_for(p.wait(), 5)


async def test_cli_survives_malformed_response(tmp_path):
    p = await start_cli(
        tmp_path,
        """
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    content = None if request['id'] == 1 else [{'type':'text','text':'ok'}]
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'content':content}}), flush=True)
""",
    )
    try:
        for n in [1, 2]:
            p.stdin.write(call(n) + b"\n")
            await p.stdin.drain()
            response = json.loads(await asyncio.wait_for(p.stdout.readline(), 5))
            assert response["id"] == n
            assert ("error" in response) == (n == 1)
        p.stdin.close()
        await asyncio.wait_for(p.wait(), 5)
        assert p.returncode == 0
    finally:
        await finish(p)


@pytest.mark.skipif(os.name == "nt", reason="POSIX file descriptor lifecycle")
async def test_cli_keeps_serving_after_stderr_eof(tmp_path):
    p = await start_cli(
        tmp_path,
        """
import json, os, sys, time
os.close(2)
time.sleep(0.1)
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'content':[]}}), flush=True)
""",
    )
    try:
        p.stdin.write(call() + b"\n")
        await p.stdin.drain()
        response = json.loads(await asyncio.wait_for(p.stdout.readline(), 5))
        assert response["id"] == 1
        assert p.returncode is None
    finally:
        await finish(p)


async def test_unexpected_proxy_failure_exits_nonzero(monkeypatch):
    p = proxy()

    async def broken():
        raise RuntimeError("forced forwarding failure")

    monkeypatch.setattr(p, "_proxy_client_to_server", broken)
    assert await p.run([sys.executable, "-c", "import time; time.sleep(30)"]) != 0


@pytest.mark.parametrize("pii_action", [Action.REDACT, Action.DENY])
async def test_multiple_findings_count_one_outbound_response(pii_action, monkeypatch):
    state = DashboardState()
    monkeypatch.setattr("mcp_firewall.proxy.stdio.dashboard_state", state)
    p = proxy()
    p.config.pii.enabled = True
    p.config.pii.action = pii_action
    await p._intercept_request(call())
    out = await p._intercept_response(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{"type": "text", "text": SECRET}],
                    "structuredContent": {"email": "alice@example.com"},
                },
            }
        ).encode()
    )
    assert SECRET.encode() not in out
    assert b"alice@example.com" not in out
    assert state.stats["total"] == 1
    assert len([e for e in state.events if e.get("direction") == "outbound"]) == 1
    assert state.stats["redacted"] == (1 if pii_action == Action.REDACT else 0)
    assert state.stats["responses_denied"] == (1 if pii_action == Action.DENY else 0)


async def test_structured_only_result_is_scanned():
    p = proxy()
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"key": SECRET}}}
    ).encode()
    assert SECRET.encode() not in await p._intercept_response(raw)


async def test_pending_bytes_bound_is_enforced(monkeypatch):
    monkeypatch.setattr("mcp_firewall.proxy.stdio.MAX_PENDING_BYTES", len(call()))
    p = proxy()
    assert await p._intercept_request(call()) is not None
    assert await p._intercept_request(call(2)) is None


async def test_audit_failure_is_not_misclassified_as_bad_server_data(monkeypatch):
    p = proxy()

    def fail(*args, **kwargs):
        raise ValueError("audit integrity failure")

    monkeypatch.setattr(p.pipeline.audit, "log", fail)
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"text": SECRET}]}}
    ).encode()
    with pytest.raises(ValueError, match="audit integrity"):
        await p._intercept_response(raw)


async def test_server_request_id_does_not_consume_client_request():
    p = proxy()
    await p._intercept_request(call())
    request = b'{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}'
    assert await p._intercept_response(request) == request
    assert len(p._pending_requests) == 1


@pytest.mark.parametrize("newline", [False, True])
async def test_message_size_limit_covers_complete_and_partial_frames(newline, monkeypatch):
    monkeypatch.setattr("mcp_firewall.proxy.stdio.MAX_MESSAGE_SIZE", 128)
    reader = asyncio.StreamReader()
    reader.feed_data(b"x" * 129 + (b"\n" if newline else b""))
    reader.feed_eof()
    with pytest.raises(ValueError, match="limit"):
        async for _ in StdioProxy._messages(reader):
            pytest.fail("oversized frame admitted")
