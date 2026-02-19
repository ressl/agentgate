"""stdio MCP proxy — transparent man-in-the-middle for MCP stdio transport."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from rich.console import Console

from ..models import Action, GatewayConfig, ToolCallRequest, ToolCallResponse
from ..pipeline.runner import PipelineRunner
from ..dashboard.app import state as dashboard_state


class StdioProxy:
    """Proxies MCP JSON-RPC over stdio, intercepting tool calls.

    Architecture:
        MCP Client (stdin/stdout) <-> mcp-firewall <-> MCP Server (subprocess stdin/stdout)

    The proxy intercepts `tools/call` requests, runs them through the inbound
    pipeline, forwards allowed calls to the server, scans responses through
    the outbound pipeline, and returns (possibly modified) responses to the client.
    """

    def __init__(self, config: GatewayConfig, console: Console | None = None) -> None:
        self.config = config
        self.pipeline = PipelineRunner(config)
        self.console = console or Console(stderr=True)
        self._server_proc: asyncio.subprocess.Process | None = None

    async def run(self, server_command: list[str]) -> int:
        """Start the proxy between stdin/stdout and the server subprocess."""
        self.console.print(
            f"[blue]mcp-firewall[/blue] wrapping: [dim]{' '.join(server_command)}[/dim]",
            highlight=False,
        )

        # Start MCP server subprocess
        self._server_proc = await asyncio.create_subprocess_exec(
            *server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # Bidirectional proxy
            client_to_server = asyncio.create_task(
                self._proxy_client_to_server()
            )
            server_to_client = asyncio.create_task(
                self._proxy_server_to_client()
            )
            server_stderr = asyncio.create_task(
                self._forward_server_stderr()
            )

            done, pending = await asyncio.wait(
                [client_to_server, server_to_client, server_stderr],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

        except asyncio.CancelledError:
            pass
        finally:
            if self._server_proc and self._server_proc.returncode is None:
                self._server_proc.terminate()
                await self._server_proc.wait()

        return self._server_proc.returncode or 0

    async def _proxy_client_to_server(self) -> None:
        """Read from client (our stdin), intercept, forward to server."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        buffer = b""
        while True:
            chunk = await reader.read(8192)
            if not chunk:
                break

            buffer += chunk

            # Process complete JSON-RPC messages (newline-delimited)
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                message = await self._intercept_request(line)
                if message is not None:
                    self._server_proc.stdin.write(message + b"\n")
                    await self._server_proc.stdin.drain()

    async def _proxy_server_to_client(self) -> None:
        """Read from server stdout, scan responses, forward to client."""
        stdout_writer = sys.stdout.buffer

        buffer = b""
        while True:
            chunk = await self._server_proc.stdout.read(8192)
            if not chunk:
                break

            buffer += chunk

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue

                message = await self._intercept_response(line)
                stdout_writer.write(message + b"\n")
                stdout_writer.flush()

    async def _forward_server_stderr(self) -> None:
        """Forward server stderr to our stderr."""
        while True:
            line = await self._server_proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def _intercept_request(self, raw: bytes) -> bytes | None:
        """Intercept and evaluate a JSON-RPC request.

        Returns the (possibly modified) message to forward, or None to drop.
        """
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw  # Not JSON, pass through

        method = msg.get("method", "")

        # Only intercept tools/call
        if method != "tools/call":
            return raw

        params = msg.get("params", {})
        request = ToolCallRequest(
            id=str(msg.get("id", "")),
            tool_name=params.get("name", ""),
            arguments=params.get("arguments", {}),
        )

        # Run inbound pipeline
        decision = self.pipeline.evaluate_inbound(request)

        if decision and decision.action == Action.DENY:
            self.console.print(
                f"  [red]✗ DENIED[/red] {request.tool_name}: {decision.reason}"
            )
            dashboard_state.add_event({
                "action": "deny", "tool": request.tool_name, "agent": request.agent_id,
                "reason": decision.reason, "severity": decision.severity.value,
                "stage": decision.stage.value if decision.stage else None,
                "timestamp": request.timestamp,
            })
            # Return error response directly to client
            error_response = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"[mcp-firewall] Blocked: {decision.reason}",
                        }
                    ],
                    "isError": True,
                },
            }
            sys.stdout.buffer.write(json.dumps(error_response).encode() + b"\n")
            sys.stdout.buffer.flush()
            return None  # Don't forward to server

        if decision and decision.action == Action.PROMPT:
            self.console.print(
                f"  [yellow]? PROMPT[/yellow] {request.tool_name}: {decision.reason}"
            )
            # In Phase 1, prompt falls through to allow (interactive approval in Phase 2)
            self.console.print(f"  [dim]  (auto-allowing, interactive approval coming in Phase 2)[/dim]")

        self.console.print(
            f"  [green]✓ ALLOW[/green]  {request.tool_name}"
        )
        dashboard_state.add_event({
            "action": "allow", "tool": request.tool_name, "agent": request.agent_id,
            "reason": "", "severity": "info", "stage": None,
            "timestamp": request.timestamp,
        })
        return raw

    async def _intercept_response(self, raw: bytes) -> bytes:
        """Intercept and scan a JSON-RPC response."""
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw

        # Only scan tool call results
        result = msg.get("result")
        if not result or "content" not in result:
            return raw

        response = ToolCallResponse(
            request_id=str(msg.get("id", "")),
            content=result.get("content", []),
            is_error=result.get("isError", False),
        )

        # Create a dummy request for pipeline (we don't have the original here)
        dummy_request = ToolCallRequest(
            id=response.request_id,
            tool_name="(response scan)",
        )

        response, decisions = self.pipeline.scan_outbound(dummy_request, response)

        for d in decisions:
            if d.action == Action.DENY:
                self.console.print(f"  [red]✗ BLOCKED RESPONSE[/red]: {d.reason}")
                msg["result"]["content"] = [
                    {"type": "text", "text": f"[mcp-firewall] Response blocked: {d.reason}"}
                ]
                msg["result"]["isError"] = True
                return json.dumps(msg).encode()
            elif d.action == Action.REDACT:
                self.console.print(f"  [yellow]~ REDACTED[/yellow]: {d.reason}")
                msg["result"]["content"] = response.content
                return json.dumps(msg).encode()

        return raw
