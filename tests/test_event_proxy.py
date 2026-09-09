"""Real stdio lifecycle and local HTTP receiver integration."""

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mcp_firewall.models import Action, EventPhase, GatewayConfig
from mcp_firewall.proxy.stdio import StdioProxy


def call(request_id):
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": "status"}}
    ).encode()


@pytest.mark.parametrize("respond", [True, False])
async def test_real_proxy_exports_correlated_lifecycle_over_http(tmp_path, respond):
    received = []

    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.headers["Idempotency-Key"], body["event"]))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    cfg = tmp_path / "gateway.yaml"
    cfg.write_text(
        "defaultAction: allow\naudit:\n  enabled: false\nevents:\n  enabled: true\n"
        f"  webhook:\n    url: http://127.0.0.1:{receiver.server_port}/events\n"
    )
    server = """
import json, sys
requests = [json.loads(sys.stdin.readline()) for _ in range(2)]
if sys.argv[1] == 'yes':
    for request in reversed(requests):
        result = {'content': [{'type': 'text', 'text': 'OK'}]}
        print(json.dumps({'jsonrpc':'2.0', 'id':request['id'], 'result':result}), flush=True)
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_firewall",
        "wrap",
        "--config",
        str(cfg),
        "--",
        sys.executable,
        "-c",
        server,
        "yes" if respond else "no",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(call(1) + b"\n" + call("1") + b"\n"), 10
        )
        assert process.returncode == 0, stderr.decode()
        assert len(stdout.splitlines()) == (2 if respond else 0)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
        await asyncio.to_thread(receiver.shutdown)
        receiver.server_close()
        thread.join(timeout=1)
    events = [item for _, item in received]
    assert len({event["session_id"] for event in events}) == 1
    assert len({event["call_id"] for event in events}) == 2
    assert [e["sequence"] for e in events] == list(range(1, len(events) + 1))
    assert all(key == item["id"] for key, item in received)
    for call_id in {event["call_id"] for event in events}:
        phases = [e["phase"] for e in events if e["call_id"] == call_id]
        assert phases[:4] == [
            "request_received",
            "policy_decision",
            "request_allowed",
            "request_forwarded",
        ]
        assert phases[-1] == ("response_allowed" if respond else "request_unknown")
    assert {type(e["request_id"]) for e in events} == {str, int}


async def test_denied_request_is_never_reported_as_forwarded(monkeypatch):
    cfg = GatewayConfig(default_action=Action.DENY)
    cfg.audit.enabled = False
    proxy = StdioProxy(cfg)
    seen = []
    proxy.pipeline.events._observer = seen.append
    monkeypatch.setattr(proxy, "_send_error", lambda *args: None)
    assert await proxy._intercept_request(call(1)) is None
    assert seen[-1].phase == EventPhase.REQUEST_DENIED
    assert EventPhase.REQUEST_FORWARDED not in [item.phase for item in seen]
    proxy._finish_pending()
    assert seen[-1].phase == EventPhase.REQUEST_DENIED
