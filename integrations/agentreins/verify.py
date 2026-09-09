#!/usr/bin/env python3
"""Run the actual AgentReins adapter against a real firewall and toy MCP server."""

# Test harness assertions are intentional.
# ruff: noqa: S101

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import signal
import socket
import sys
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
SERVER = r"""
import json, os, sys
from pathlib import Path
for line in sys.stdin:
    request = json.loads(line)
    if request['params']['name'] == 'edit_workspace':
        (Path(sys.argv[2]) / 'example.txt').write_text('tool change\n')
    with Path(sys.argv[1]).open('a') as output:
        output.write(line)
    assert 'MCP_FIREWALL_DASHBOARD_TOKEN' not in os.environ
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {
        'content': [{'type': 'text', 'text': 'AKIAIOSFODNN7EXAMPLE'}]}}), flush=True)
"""


@contextmanager
def fault_server(root: Path):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == "/redirected":
                (root / "redirect-followed").touch()
            mode = parse_qs(url.query).get("after", ["0"])[0]
            if mode == "0":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(5 * 1024 * 1024))
            self.end_headers()
            try:
                self.wfile.write(b"x" * (5 * 1024 * 1024))
            except (BrokenPipeError, ConnectionResetError):
                pass

        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                pass  # Rejecting an oversized response may reset the fixture socket.

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


async def verify(checkout: Path, root: Path, fault_url: str) -> None:
    build = await asyncio.create_subprocess_exec(
        "swift",
        "build",
        "--build-tests",
        "--package-path",
        str(checkout),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await build.communicate()
    if build.returncode:
        print(output.decode())
        raise RuntimeError("AgentReins build failed")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "example.txt").write_text("original\n")
    token = secrets.token_urlsafe(32)
    config = root / "firewall.yaml"
    config.write_text(
        "defaultAction: prompt\naudit:\n  enabled: false\nrules:\n"
        "  - name: hard-denial\n    tool: danger\n    action: deny\n"
    )
    proxy = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_firewall",
        "wrap",
        "--config",
        str(config),
        "--dashboard-approvals",
        "--snapshot-workspace",
        str(workspace),
        "--dashboard-port",
        str(port),
        "--",
        sys.executable,
        "-c",
        SERVER,
        str(root / "executed.jsonl"),
        str(workspace),
        cwd=ROOT,
        env={**os.environ, "MCP_FIREWALL_DASHBOARD_TOKEN": token},
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    swift = None
    try:
        import httpx

        async with httpx.AsyncClient(trust_env=False) as client:
            for _ in range(100):
                try:
                    response = await client.get(f"http://127.0.0.1:{port}/api/approval-mode")
                    if response.status_code == 200:
                        break
                except httpx.ConnectError:
                    pass
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("Firewall did not start")
        swift = await asyncio.create_subprocess_exec(
            "swift",
            "test",
            "--package-path",
            str(checkout),
            "--filter",
            "MCPFirewallAdapterTests",
            env={
                **os.environ,
                "MCP_FIREWALL_TEST_URL": f"http://127.0.0.1:{port}",
                "MCP_FIREWALL_TEST_TOKEN": token,
                "MCP_FIREWALL_TEST_DIRECTORY": str(root),
                "MCP_FIREWALL_TEST_FAULT_URL": fault_url,
            },
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )

        async def wait_for(name: str) -> None:
            async with asyncio.timeout(30):
                while not (root / name).exists():
                    if swift.returncode is not None:
                        raise RuntimeError(
                            "Swift controller stopped before completing verification"
                        )
                    await asyncio.sleep(0.025)

        async def call(number: int, tool: str, *, secret: bool = False) -> dict:
            assert proxy.stdin and proxy.stdout
            proxy.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": number,
                        "method": "tools/call",
                        "params": {
                            "name": tool,
                            "arguments": {"password": "private-test-value"} if secret else {},
                        },
                    }
                ).encode()
                + b"\n"
            )
            await proxy.stdin.drain()
            return json.loads(await asyncio.wait_for(proxy.stdout.readline(), 25))

        await wait_for("ready")
        allowed = await call(1, "status", secret=True)
        assert "result" in allowed and "AKIAIOSFODNN7EXAMPLE" not in json.dumps(allowed)
        await wait_for("allowed-verified")
        assert "error" in await call(2, "danger")
        await wait_for("hard-denial-verified")
        assert "error" in await call(3, "rejectable")
        await wait_for("denied-verified")
        assert "error" in await call(4, "disconnectable")
        await wait_for("disconnected")
        (root / "disconnect-verified").touch()
        await wait_for("lease-ready")
        assert "error" in await call(5, "lease_lost")
        await wait_for("lease-dropped")
        (root / "lease-verified").touch()
        await wait_for("workspace-ready")
        assert "result" in await call(6, "edit_workspace")
        await wait_for("restore-verified")
        assert (workspace / "example.txt").read_text() == "original\n"
        (root / "restore-ack").touch()
        await wait_for("second-edit-ready")
        assert "result" in await call(7, "edit_workspace")
        await wait_for("conflict-verified")
        assert (workspace / "example.txt").read_text() == "later user edit\n"
        (root / "conflict-ack").touch()
        await wait_for("finished")
        stdout, _ = await asyncio.wait_for(swift.communicate(), 10)
        print(stdout.decode().replace(token, "[REDACTED]"))
        if swift.returncode:
            raise RuntimeError("Swift integration tests failed")
        assert len((root / "executed.jsonl").read_text().splitlines()) == 3
        assert not (root / "redirect-followed").exists()
        print(
            "PASS: native approval, real execution, response redaction, "
            "hard/user denial, replay, lease loss, native file restore and later-edit conflict"
        )
    finally:
        for process in [swift, proxy]:
            if process is not None and process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await process.wait()
        if swift is not None and swift.stdout is not None:
            remaining = await swift.stdout.read()
            if remaining:
                print(remaining.decode().replace(token, "[REDACTED]"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-firewall-agentreins-test-") as directory:
        with fault_server(Path(directory)) as fault_url:
            asyncio.run(verify(args.checkout.resolve(strict=True), Path(directory), fault_url))


if __name__ == "__main__":
    main()
