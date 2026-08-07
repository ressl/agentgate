"""stdio MCP proxy — transparent man-in-the-middle for MCP stdio transport."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from typing import Any

from pydantic import ValidationError
from rich.console import Console

from ..models import Action, GatewayConfig, ToolCallRequest, ToolCallResponse
from ..pipeline.runner import PipelineRunner
from ..dashboard.app import state as dashboard_state

# Maximum size of a single newline-delimited JSON-RPC message
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB


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
        # stdin is the JSON-RPC protocol channel here — interactive approval
        # prompts are impossible, so approval requests fail closed.
        self.pipeline = PipelineRunner(config, stdin_available=False)
        self.console = console or Console(stderr=True)
        self._server_proc: asyncio.subprocess.Process | None = None
        # Agent identity captured from the initialize handshake (clientInfo)
        self._agent_id = "unknown"

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

            # Surface exceptions from finished tasks instead of swallowing them
            for task in done:
                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is not None:
                    self.console.print(f"[red]Proxy task failed:[/red] {exc!r}")

            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

        except asyncio.CancelledError:
            pass
        finally:
            if self._server_proc and self._server_proc.returncode is None:
                self._server_proc.terminate()
                try:
                    await asyncio.wait_for(self._server_proc.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    self._server_proc.kill()
                    await self._server_proc.wait()

        return self._exit_code(self._server_proc.returncode)

    @staticmethod
    def _exit_code(returncode: int | None) -> int:
        """Map the server return code to a proxy exit code.

        A server terminated by our own SIGTERM during shutdown is a clean
        exit, not an error (sys.exit(-15) would surface as 241).
        """
        if returncode is None or returncode == -signal.SIGTERM:
            return 0
        return returncode

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

            if len(buffer) > MAX_MESSAGE_SIZE:
                self.console.print(
                    "[red]Client message exceeds 10 MB limit, closing connection[/red]"
                )
                break

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

            if len(buffer) > MAX_MESSAGE_SIZE:
                self.console.print(
                    "[red]Server message exceeds 10 MB limit, closing connection[/red]"
                )
                break

    async def _forward_server_stderr(self) -> None:
        """Forward server stderr to our stderr."""
        while True:
            line = await self._server_proc.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        """Send a JSON-RPC error response to the client."""
        error_response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }
        sys.stdout.buffer.write(json.dumps(error_response).encode() + b"\n")
        sys.stdout.buffer.flush()

    def _capture_agent_identity(self, msg: dict[str, Any]) -> None:
        """Capture clientInfo.name from the initialize handshake as agent_id."""
        params = msg.get("params")
        if not isinstance(params, dict):
            return
        client_info = params.get("clientInfo")
        if not isinstance(client_info, dict):
            return
        name = client_info.get("name")
        if isinstance(name, str) and name:
            self._agent_id = name

    async def _intercept_request(self, raw: bytes) -> bytes | None:
        """Intercept and evaluate a JSON-RPC request.

        Returns the (possibly modified) message to forward, or None to drop.
        Malformed messages are logged and skipped — they must never crash
        the proxy.
        """
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            return raw  # Not JSON, pass through

        if not isinstance(msg, dict):
            self.console.print("  [red]✗ INVALID[/red] non-object JSON-RPC message dropped")
            return None

        method = msg.get("method", "")

        # Capture agent identity from the initialize handshake
        if method == "initialize":
            self._capture_agent_identity(msg)

        # Only intercept tools/call
        if method != "tools/call":
            return raw

        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}

        try:
            request = ToolCallRequest(
                id=str(msg.get("id", "")),
                tool_name=params.get("name", ""),
                arguments=params.get("arguments", {}),
                agent_id=self._agent_id,
            )
        except ValidationError:
            self.console.print("  [red]✗ INVALID[/red] malformed tools/call request")
            if "id" in msg:
                self._send_error(msg.get("id"), -32602, "Invalid params")
            return None

        # Run inbound pipeline (approval prompts run off the event loop)
        decision = await self.pipeline.aevaluate_inbound(request)

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
            # Return JSON-RPC error directly to client (notifications get none)
            if "id" in msg:
                self._send_error(
                    msg.get("id"), -32000, f"[mcp-firewall] Blocked: {decision.reason}"
                )
            return None  # Don't forward to server

        if decision and decision.action == Action.PROMPT:
            self.console.print(
                f"  [yellow]? PROMPT[/yellow] {request.tool_name}: {decision.reason}"
            )

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

        if not isinstance(msg, dict):
            return raw  # Not a JSON-RPC object, pass through

        # Only scan tool call results
        result = msg.get("result")
        if not isinstance(result, dict) or "content" not in result:
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

        # Evaluate ALL decisions — DENY wins regardless of stage order
        deny = next((d for d in decisions if d.action == Action.DENY), None)
        if deny:
            self.console.print(f"  [red]✗ BLOCKED RESPONSE[/red]: {deny.reason}")
            msg["result"]["content"] = [
                {"type": "text", "text": f"[mcp-firewall] Response blocked: {deny.reason}"}
            ]
            msg["result"]["isError"] = True
            return json.dumps(msg).encode()

        for d in decisions:
            if d.action == Action.REDACT:
                self.console.print(f"  [yellow]~ REDACTED[/yellow]: {d.reason}")
                msg["result"]["content"] = response.content
                return json.dumps(msg).encode()

        return raw
