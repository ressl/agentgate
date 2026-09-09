"""stdio MCP proxy — transparent man-in-the-middle for MCP stdio transport."""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from collections.abc import AsyncIterator
from typing import Any

from pydantic import ValidationError
from rich.console import Console

from ..dashboard.app import state as dashboard_state
from ..models import Action, GatewayConfig, ToolCallRequest, ToolCallResponse
from ..pipeline.outbound.content import ResponseContentError
from ..pipeline.runner import PipelineRunner

# Maximum size of a single newline-delimited JSON-RPC message
MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_PENDING_REQUESTS = 1000
MAX_PENDING_BYTES = 10 * 1024 * 1024


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
        self._pending_requests: dict[tuple[type, Any], ToolCallRequest] = {}
        self._pending_sizes: dict[tuple[type, Any], int] = {}
        self._pending_bytes = 0

    async def run(self, server_command: list[str]) -> int:
        """Run the protocol streams; diagnostic EOF does not end a session."""
        self.console.print(
            f"[blue]mcp-firewall[/blue] wrapping: [dim]{' '.join(server_command)}[/dim]",
            highlight=False,
        )
        self._server_proc = await asyncio.create_subprocess_exec(
            *server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        client = asyncio.create_task(self._proxy_client_to_server())
        server = asyncio.create_task(self._proxy_server_to_client())
        diagnostics = asyncio.create_task(self._forward_server_stderr())
        tasks = [client, server, diagnostics]
        failed = False
        try:
            done, _ = await asyncio.wait([client, server], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    failed = True
                    self.console.print(f"[red]Proxy task failed:[/red] {task.exception()!r}")
            if client in done and not failed and not server.done():
                # Half-close stdin and let the server finish outstanding responses.
                if self._server_proc.stdin is not None:
                    self._server_proc.stdin.close()
                try:
                    await asyncio.wait_for(server, timeout=5.0)
                except TimeoutError:
                    failed = bool(self._pending_requests)
                except Exception as exc:
                    failed = True
                    self.console.print(f"[red]Proxy task failed:[/red] {exc!r}")
        except asyncio.CancelledError:
            pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if diagnostics.done() and not diagnostics.cancelled() and diagnostics.exception():
                self.console.print("[yellow]Server diagnostic forwarding stopped[/yellow]")
            if self._server_proc.returncode is None:
                try:
                    self._server_proc.terminate()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(self._server_proc.wait(), timeout=5.0)
                except TimeoutError:
                    self._server_proc.kill()
                    await self._server_proc.wait()
            self._pending_requests.clear()
            self._pending_sizes.clear()
            self._pending_bytes = 0
        return 1 if failed else self._exit_code(self._server_proc.returncode)

    @staticmethod
    def _exit_code(returncode: int | None) -> int:
        """Map the server return code to a proxy exit code.

        A server terminated by our own SIGTERM during shutdown is a clean
        exit, not an error (sys.exit(-15) would surface as 241).
        """
        if returncode is None or returncode == -signal.SIGTERM:
            return 0
        return returncode

    @staticmethod
    async def _messages(reader: asyncio.StreamReader) -> AsyncIterator[bytes]:
        """Bound complete messages and partial frames in both directions."""
        buffer = bytearray()
        while chunk := await reader.read(8192):
            parts = chunk.split(b"\n")
            for i, part in enumerate(parts):
                if len(buffer) + len(part) > MAX_MESSAGE_SIZE:
                    raise ValueError("JSON-RPC message exceeds 10 MB limit")
                buffer.extend(part)
                if i < len(parts) - 1:
                    line = bytes(buffer).strip()
                    buffer.clear()
                    if line:
                        yield line
        if buffer.strip():
            raise ValueError("Unterminated JSON-RPC message")

    async def _proxy_client_to_server(self) -> None:
        if self._server_proc is None or self._server_proc.stdin is None:
            raise RuntimeError("Server stdin is unavailable")
        writer = self._server_proc.stdin
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await asyncio.get_running_loop().connect_read_pipe(
            lambda: protocol, sys.stdin.buffer
        )
        try:
            async for line in self._messages(reader):
                message = await self._intercept_request(line)
                if message is not None:
                    writer.write(message + b"\n")
                    await writer.drain()
        finally:
            transport.close()

    async def _proxy_server_to_client(self) -> None:
        if self._server_proc is None or self._server_proc.stdout is None:
            raise RuntimeError("Server stdout is unavailable")
        async for line in self._messages(self._server_proc.stdout):
            message = await self._intercept_response(line)
            if message is not None:
                sys.stdout.buffer.write(message + b"\n")
                sys.stdout.buffer.flush()

    async def _forward_server_stderr(self) -> None:
        if self._server_proc is None or self._server_proc.stderr is None:
            return
        while chunk := await self._server_proc.stderr.read(8192):
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()

    @staticmethod
    def _error_bytes(request_id: Any, code: int, message: str) -> bytes:
        return json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        ).encode()

    @staticmethod
    def _request_key(request_id: Any) -> tuple[type, Any] | None:
        # JSON-RPC distinguishes integer 1 from string "1"; bool is not an ID.
        if type(request_id) in (int, str):
            return type(request_id), request_id
        return None

    def _send_error(self, request_id: Any, code: int, message: str) -> None:
        """Send a JSON-RPC error response to the client."""
        error_response = {
            "jsonrpc": "2.0",
            "id": request_id if self._request_key(request_id) is not None else None,
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
        except (ValueError, RecursionError):
            self._send_error(None, -32700, "Invalid JSON-RPC encoding")
            return None

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
        if (
            not isinstance(params, dict)
            or not isinstance(params.get("name"), str)
            or not params["name"]
        ):
            if "id" in msg:
                self._send_error(msg.get("id"), -32602, "Invalid params")
            return None

        key = self._request_key(msg.get("id"))
        if "id" in msg and key is None:
            self._send_error(None, -32600, "Invalid request ID")
            return None
        if key is not None and (
            key in self._pending_requests
            or len(self._pending_requests) >= MAX_PENDING_REQUESTS
            or self._pending_bytes + len(raw) > MAX_PENDING_BYTES
        ):
            self._send_error(msg["id"], -32000, "Duplicate ID or too many pending requests")
            return None

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
            self.console.print(f"  [red]✗ DENIED[/red] {request.tool_name}: {decision.reason}")
            dashboard_state.add_event(
                {
                    "action": "deny",
                    "tool": request.tool_name,
                    "agent": request.agent_id,
                    "reason": decision.reason,
                    "severity": decision.severity.value,
                    "stage": decision.stage.value if decision.stage else None,
                    "timestamp": request.timestamp,
                }
            )
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

        self.console.print(f"  [green]✓ ALLOW[/green]  {request.tool_name}")
        dashboard_state.add_event(
            {
                "action": "allow",
                "tool": request.tool_name,
                "agent": request.agent_id,
                "reason": "",
                "severity": "info",
                "stage": None,
                "timestamp": request.timestamp,
            }
        )
        if key is not None:
            self._pending_requests[key] = request
            self._pending_sizes[key] = len(raw)
            self._pending_bytes += len(raw)
        return raw

    async def _intercept_response(self, raw: bytes) -> bytes | None:
        """Validate and scan complete tool results, keeping request attribution."""
        try:
            msg = json.loads(raw)
        except (ValueError, RecursionError):
            self.console.print("[red]Invalid JSON-RPC response dropped[/red]")
            return None
        if not isinstance(msg, dict):
            return None
        # Server-initiated requests have their own ID namespace.
        if "method" in msg:
            if "result" in msg or "error" in msg:
                return self._error_bytes(None, -32603, "Ambiguous server message")
            return raw
        key = self._request_key(msg.get("id"))
        request = self._pending_requests.pop(key, None) if key is not None else None
        if key is not None:
            self._pending_bytes -= self._pending_sizes.pop(key, 0)
        result = msg.get("result")
        if request is None and (
            not isinstance(result, dict)
            or not ("content" in result or "structuredContent" in result)
        ):
            return raw
        if request is not None and "error" in msg:
            return raw
        request = request or ToolCallRequest(
            id=str(msg.get("id", "")),
            tool_name="(unmatched response)",
            agent_id=self._agent_id,
        )
        try:
            if not isinstance(result, dict) or not isinstance(result.get("isError", False), bool):
                raise ValueError("Invalid tool result")
            response = ToolCallResponse(
                request_id=request.id,
                content=result.get("content", []),
                structured_content=result.get("structuredContent"),
                extra_fields={
                    k: v
                    for k, v in result.items()
                    if k
                    not in {
                        "content",
                        "structuredContent",
                        "isError",
                    }
                },
                is_error=result.get("isError", False),
            )
        except (ValueError, TypeError, RecursionError):
            self.console.print("[red]Invalid tool result blocked[/red]")
            return self._error_bytes(msg.get("id"), -32603, "Invalid tool result from server")

        try:
            response, decisions = self.pipeline.scan_outbound(request, response)
        except ResponseContentError:
            return self._error_bytes(msg.get("id"), -32603, "Tool result cannot be safely scanned")

        deny = next((d for d in decisions if d.action == Action.DENY), None)
        if decisions:
            decision = deny or next(
                (d for d in decisions if d.action == Action.REDACT), decisions[0]
            )
            dashboard_state.add_event(
                {
                    "direction": "outbound",
                    "request_id": msg.get("id"),
                    "action": decision.action.value,
                    "tool": request.tool_name,
                    "agent": request.agent_id,
                    "reason": "; ".join(d.reason for d in decisions),
                    "severity": max(d.severity for d in decisions).value,
                    "stage": decision.stage.value,
                    "findings": [d.model_dump(mode="json") for d in decisions],
                    "timestamp": response.timestamp,
                }
            )
        if deny:
            self.console.print(f"[red]Blocked response:[/red] {deny.reason}")
            # Rebuild the envelope too: no original output survives a deny.
            return json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": msg.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"[mcp-firewall] Response blocked: {deny.reason}",
                            }
                        ],
                        "isError": True,
                    },
                }
            ).encode()
        if any(d.action == Action.REDACT for d in decisions):
            cleaned = {**response.extra_fields, "content": response.content}
            if "structuredContent" in result:
                cleaned["structuredContent"] = response.structured_content
            if "isError" in result:
                cleaned["isError"] = response.is_error
            msg["result"] = cleaned
            return json.dumps(msg).encode()
        return raw
