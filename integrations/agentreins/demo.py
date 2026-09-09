#!/usr/bin/env python3
"""Run the real native adapter in an isolated app with a synthetic MCP workspace."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import plistlib
import shutil
import signal
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Public synthetic fixture credential, never suitable for a real controller.
DEMO_TOKEN = "mcp-firewall-isolated-demo-credential-only"  # noqa: S105
APP = """import SwiftUI

@main
struct MCPFirewallDemoApp: App {
    @StateObject private var sight = MCPFirewallSight()
    @State private var showing = true
    var body: some Scene {
        WindowGroup("AgentReins · MCP Firewall demo") {
            VStack(spacing: 20) {
                Text("Isolated AgentReins adapter demo").font(.title2)
                Text("Synthetic workspace only. No agent history or OS monitors.")
                Button("MCP Firewall") { showing = true }
            }.padding(40).frame(minWidth: 760, minHeight: 620)
            .sheet(isPresented: $showing) { MCPFirewallView(sight: sight) }
            .onAppear { NSApplication.shared.activate(ignoringOtherApps: true) }
        }
    }
}
"""
SERVER = """import json, sys
from pathlib import Path
workspace = Path(sys.argv[1])
for line in sys.stdin:
    request = json.loads(line)
    if request['params']['name'] == 'demo_write':
        (workspace / 'example.txt').write_text('Changed by the synthetic MCP tool.\\n')
    with (workspace.parent / 'executed.jsonl').open('a') as log:
        log.write(line)
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {
        'content': [{'type': 'text', 'text': 'Demo operation finished.'}]}}), flush=True)
"""


async def run(checkout: Path, root: Path, snapshots: bool) -> None:
    package = root / "package"
    package.mkdir()
    shutil.copy2(checkout / "Package.swift", package / "Package.swift")
    shutil.copytree(checkout / "Sources", package / "Sources")
    shutil.copytree(checkout / "Tests", package / "Tests")
    (package / "Sources/AgentReins/AgentGuardApp.swift").write_text(APP)
    build = await asyncio.create_subprocess_exec(
        "swift",
        "build",
        "--package-path",
        str(package),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await build.communicate()
    if build.returncode:
        raise RuntimeError(output.decode())
    bundle = root / "MCP Firewall Demo.app"
    executable = bundle / "Contents/MacOS/AgentReins"
    executable.parent.mkdir(parents=True)
    shutil.copy2(package / ".build/debug/AgentReins", executable)
    with (bundle / "Contents/Info.plist").open("wb") as stream:
        plistlib.dump(
            {
                "CFBundleExecutable": "AgentReins",
                "CFBundleName": "MCP Firewall Demo",
                "CFBundleIdentifier": "it.ressl.mcp-firewall.isolated-demo",
                "CFBundlePackageType": "APPL",
                "NSHighResolutionCapable": True,
            },
            stream,
        )
    workspace = root / "workspace"
    workspace.mkdir()
    (workspace / "example.txt").write_text("Original demo content.\n")
    (root / "firewall.yaml").write_text("defaultAction: prompt\naudit:\n  enabled: false\n")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    args = [
        sys.executable,
        "-m",
        "mcp_firewall",
        "wrap",
        "--config",
        str(root / "firewall.yaml"),
        "--dashboard-approvals",
        "--approval-timeout",
        "300",
        "--dashboard-port",
        str(port),
    ]
    if snapshots:
        args += ["--snapshot-workspace", str(workspace)]
    args += ["--", sys.executable, "-c", SERVER, str(workspace)]
    proxy = await asyncio.create_subprocess_exec(
        *args,
        cwd=ROOT,
        env={**os.environ, "MCP_FIREWALL_DASHBOARD_TOKEN": DEMO_TOKEN},
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    app = None
    try:
        import httpx

        async with httpx.AsyncClient(trust_env=False) as client:
            for _ in range(200):
                try:
                    if (await client.get(f"http://127.0.0.1:{port}/api/approval-mode")).is_success:
                        break
                except httpx.ConnectError:
                    pass
                if proxy.returncode is not None:
                    raise RuntimeError("Demo proxy failed to start")
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("Demo proxy did not start")
        app = await asyncio.create_subprocess_exec(
            str(executable),
            start_new_session=True,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        print(
            f"APP: {bundle}\nURL: http://127.0.0.1:{port}\n"
            f"FIXTURE TOKEN: {DEMO_TOKEN}\nWORKSPACE: {workspace}",
            flush=True,
        )
        print(
            "Commands: write, deny, disconnect (send a call); edit-user; inspect; quit", flush=True
        )
        number = 0
        while True:
            try:
                command = (await asyncio.to_thread(input)).strip()
            except EOFError:
                break
            if command == "quit":
                break
            if command == "edit-user":
                (workspace / "example.txt").write_text("Later user edit: preserve me.\n")
                print("Applied synthetic later user edit.", flush=True)
                continue
            if command == "inspect":
                print((workspace / "example.txt").read_text(), flush=True)
                print(
                    "Executed calls:",
                    (root / "executed.jsonl").read_text()
                    if (root / "executed.jsonl").exists()
                    else "none",
                    flush=True,
                )
                continue
            if command not in {"write", "deny", "disconnect"}:
                continue
            number += 1
            request = {
                "jsonrpc": "2.0",
                "id": number,
                "method": "tools/call",
                "params": {
                    "name": "demo_write" if command == "write" else f"demo_{command}",
                    "arguments": {"note": "Synthetic demo only"},
                },
            }
            if proxy.stdin is None or proxy.stdout is None:
                raise RuntimeError("Proxy streams unavailable")
            proxy.stdin.write(json.dumps(request).encode() + b"\n")
            await proxy.stdin.drain()
            print("Waiting for native approval…", flush=True)
            response = await asyncio.wait_for(proxy.stdout.readline(), 310)
            print("RESPONSE:", response.decode().strip(), flush=True)
    finally:
        for process in [app, proxy]:
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checkout", type=Path, help="Dedicated checkout with adapter installed")
    parser.add_argument("--snapshots", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-firewall-native-demo-") as directory:
        asyncio.run(run(args.checkout.resolve(strict=True), Path(directory), args.snapshots))


if __name__ == "__main__":
    main()
