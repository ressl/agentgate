"""End-to-end approval control over real HTTP and MCP stdio pipes."""

import asyncio
import json
import os
import socket
import sys
import time

import httpx
import pytest


@pytest.fixture
async def wrapped_server(tmp_path):
    marker = tmp_path / "executed.jsonl"
    config = tmp_path / "firewall.yaml"
    config.write_text(
        "defaultAction: prompt\naudit:\n  enabled: false\nrules:\n"
        "  - name: hard-denial\n    tool: danger\n    action: deny\n"
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    credential = "synthetic-proxy-approval-test-" * 2
    server = """
import json, os, sys
from pathlib import Path
for line in sys.stdin:
    request = json.loads(line)
    with Path(sys.argv[1]).open('a') as output:
        output.write(line)
    text = 'credential-leaked' if 'MCP_FIREWALL_DASHBOARD_TOKEN' in os.environ else 'OK'
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'],
        'result': {'content': [{'type': 'text', 'text': text}]}}), flush=True)
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_firewall",
        "wrap",
        "--config",
        str(config),
        "--dashboard-approvals",
        "--dashboard-port",
        str(port),
        "--",
        sys.executable,
        "-c",
        server,
        str(marker),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "MCP_FIREWALL_DASHBOARD_TOKEN": credential},
    )
    async with httpx.AsyncClient(
        base_url=f"http://127.0.0.1:{port}",
        trust_env=False,
        headers={"Authorization": f"Bearer {credential}"},
        timeout=2,
    ) as client:
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    response = await client.get("/api/approvals")
                    assert response.status_code == 200
                    break
                except httpx.ConnectError:
                    assert time.monotonic() < deadline, "Dashboard did not start"
                    await asyncio.sleep(0.02)
            yield process, client, marker
        finally:
            if process.stdin is not None:
                process.stdin.close()
            try:
                await asyncio.wait_for(process.wait(), 3)
            except TimeoutError:
                process.kill()
                await process.wait()
            stderr = await process.stderr.read()
            assert credential not in stderr.decode()


async def send(process, request_id, tool="status"):
    process.stdin.write(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {"scope": "local"}},
            }
        ).encode()
        + b"\n"
    )
    await process.stdin.drain()


async def next_pending(client):
    for _ in range(100):
        items = (await client.get("/api/approvals")).json()
        if items:
            return items[0]
        await asyncio.sleep(0.01)
    pytest.fail("No pending request appeared")


async def test_http_approval_gates_real_server_execution(wrapped_server):
    process, client, marker = wrapped_server
    await send(process, 1, "danger")
    denied = json.loads(await asyncio.wait_for(process.stdout.readline(), 2))
    assert "error" in denied
    assert (await client.get("/api/approvals")).json() == []
    await send(process, 2)
    item = await next_pending(client)
    assert not marker.exists()
    response = await client.post(
        f"/api/approvals/{item['id']}",
        json={
            "request_hash": item["request_hash"],
            "allow": True,
        },
    )
    assert response.status_code == 200
    result = json.loads(await asyncio.wait_for(process.stdout.readline(), 2))
    assert result["result"]["content"][0]["text"] == "OK"
    assert [json.loads(line)["id"] for line in marker.read_text().splitlines()] == [2]
    for request_id, decision in [(3, "deny"), (4, "disconnect")]:
        await send(process, request_id)
        item = await next_pending(client)
        if decision == "disconnect":
            response = await client.post("/api/approvals/disconnect")
        else:
            response = await client.post(
                f"/api/approvals/{item['id']}",
                json={
                    "request_hash": item["request_hash"],
                    "allow": False,
                },
            )
        assert response.status_code == 200
        assert "error" in json.loads(await asyncio.wait_for(process.stdout.readline(), 2))
    assert len(marker.read_text().splitlines()) == 1


async def test_client_eof_cancels_pending_approval(wrapped_server):
    process, client, marker = wrapped_server
    await send(process, 1)
    await next_pending(client)
    process.stdin.close()
    await asyncio.wait_for(process.wait(), 2)
    assert not marker.exists()
