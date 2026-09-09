"""Public embedding API for admission, response scanning, and lifecycle events.

Use ``with Gateway(...) as gateway`` (or ``async with``), retain the context from
``check``/``acheck``, and supply it when scanning the matching tool response. The
SDK evaluates supplied data; it never executes tools or claims that they ran.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from .audit.logger import AuditLogger
from .config import load_config
from .events import DeliveryStats, EventHandler
from .models import (
    Action,
    EventPhase,
    GatewayConfig,
    PipelineDecision,
    ToolCallRequest,
    ToolCallResponse,
)
from .pipeline.outbound.content import ResponseContentError
from .pipeline.runner import PipelineRunner


@dataclass(frozen=True)
class CallContext:
    """Correlation metadata, not a permission token or proof of execution."""

    session_id: str
    call_id: str
    tool_name: str
    agent_id: str
    arguments_hash: str
    allowed: bool


@dataclass
class CheckResult:
    blocked: bool
    action: str
    reason: str
    severity: str
    stage: str | None
    context: CallContext | None = None

    @property
    def allowed(self) -> bool:
        return not self.blocked


@dataclass
class ScanResult:
    """Text scan result; denied content is always empty."""

    content: str
    modified: bool
    findings: list[dict[str, str]]
    blocked: bool = False


@dataclass
class StructuredScanResult:
    """Complete MCP response scan result; denial contains no original payload."""

    response: ToolCallResponse
    modified: bool
    findings: list[dict[str, str]]
    blocked: bool = False


class Gateway:
    """Thread-safe admission and response scanning with explicit resource lifetime.

    Async methods offload blocking work and serialize access to shared policy
    state. Cancellation stops waiting; it cannot forcibly cancel a running Python
    worker or DNS call. No SDK operation executes or forwards a tool.
    """

    def __init__(
        self,
        config_path: str | Path | None = None,
        config: GatewayConfig | None = None,
        auto_approve: bool = False,
        *,
        event_handler: EventHandler | None = None,
    ) -> None:
        if config is not None and config_path is not None:
            raise ValueError("Pass config or config_path, not both")
        self._config_path = config_path
        self._config = (
            config.model_copy(deep=True) if config is not None else load_config(config_path)
        )
        self._lock = threading.RLock()
        self._closed = False
        self._pipeline = PipelineRunner(
            self._config,
            auto_approve=auto_approve,
            stdin_available=False,
            event_handler=event_handler,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Gateway is closed")

    def check(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        agent: str = "default",
    ) -> CheckResult:
        with self._lock:
            self._ensure_open()
            request = ToolCallRequest(
                tool_name=tool_name,
                arguments=arguments or {},
                agent_id=agent,
            ).model_copy(deep=True)
            decision = self._pipeline.evaluate_inbound(request)
            blocked = decision is not None and decision.action == Action.DENY
            context = CallContext(
                session_id=self._pipeline.events.session_id,
                call_id=request.call_id,
                tool_name=tool_name,
                agent_id=agent,
                arguments_hash=AuditLogger._hash_arguments(request.arguments),
                allowed=not blocked,
            )
            return CheckResult(
                blocked=blocked,
                action=decision.action.value if decision else "allow",
                reason=decision.reason if decision else "",
                severity=decision.severity.value if decision else "info",
                stage=decision.stage.value if decision else None,
                context=context,
            )

    async def acheck(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        agent: str = "default",
    ) -> CheckResult:
        return await asyncio.to_thread(self.check, tool_name, arguments, agent)

    def _response_request(
        self,
        context: CallContext | None,
        tool_name: str,
        agent: str,
    ) -> ToolCallRequest:
        if context is None:
            return ToolCallRequest(tool_name=tool_name, agent_id=agent, correlated=False)
        if context.session_id != self._pipeline.events.session_id:
            raise ValueError("Response context belongs to another gateway session")
        if not context.allowed:
            raise ValueError("Cannot attach a response to a denied call")
        return ToolCallRequest(
            call_id=context.call_id,
            tool_name=context.tool_name,
            agent_id=context.agent_id,
            arguments_hash=context.arguments_hash,
        )

    @staticmethod
    def _findings(decisions: list[PipelineDecision]) -> list[dict[str, str]]:
        return [
            {
                "stage": decision.stage.value,
                "severity": decision.severity.value,
                "reason": decision.reason,
                "action": decision.action.value,
            }
            for decision in decisions
        ]

    def scan_tool_response(
        self,
        response: ToolCallResponse,
        *,
        context: CallContext | None = None,
        tool_name: str = "",
        agent: str = "default",
    ) -> StructuredScanResult:
        """Scan content, embedded resources, structured content, and extensions."""
        with self._lock:
            self._ensure_open()
            request = self._response_request(context, tool_name, agent)
            try:
                response = response.model_copy(deep=True, update={"request_id": request.call_id})
                response, decisions = self._pipeline.scan_outbound(request, response)
                findings = self._findings(decisions)
                blocked = any(d.action == Action.DENY for d in decisions)
                modified = any(d.action == Action.REDACT for d in decisions)
            except (ResponseContentError, RecursionError) as exc:
                if isinstance(exc, RecursionError):
                    self._pipeline.events.emit(request, EventPhase.RESPONSE_RECEIVED)
                    self._pipeline.events.emit(
                        request,
                        EventPhase.RESPONSE_DENIED,
                        reason="Response nesting exceeds scan limit",
                    )
                blocked, modified = True, False
                findings = [
                    {
                        "stage": "response_validation",
                        "severity": "high",
                        "action": "deny",
                        "reason": "Response cannot be safely scanned",
                    }
                ]
            if blocked:
                response = ToolCallResponse(request_id=request.call_id, is_error=True)
            return StructuredScanResult(response, modified, findings, blocked)

    async def ascan_tool_response(
        self,
        response: ToolCallResponse,
        *,
        context: CallContext | None = None,
        tool_name: str = "",
        agent: str = "default",
    ) -> StructuredScanResult:
        return await asyncio.to_thread(
            self.scan_tool_response,
            response,
            context=context,
            tool_name=tool_name,
            agent=agent,
        )

    def scan_response(
        self,
        content: str,
        tool_name: str = "",
        agent: str = "default",
        *,
        context: CallContext | None = None,
    ) -> ScanResult:
        """Text convenience API. Supply check.context to correlate the response."""
        response = ToolCallResponse(request_id="", content=[{"type": "text", "text": content}])
        result = self.scan_tool_response(
            response, context=context, tool_name=tool_name, agent=agent
        )
        text = "" if result.blocked else str(result.response.content[0]["text"])
        return ScanResult(text, result.modified, result.findings, result.blocked)

    async def ascan_response(
        self,
        content: str,
        tool_name: str = "",
        agent: str = "default",
        *,
        context: CallContext | None = None,
    ) -> ScanResult:
        return await asyncio.to_thread(
            self.scan_response,
            content,
            tool_name,
            agent,
            context=context,
        )

    def reload(self, config_path: str | Path | None = None) -> None:
        with self._lock:
            self._ensure_open()
            path = config_path if config_path is not None else self._config_path
            config = load_config(path)
            self._pipeline.reload_config(config)
            self._config = config
            self._config_path = path

    async def areload(self, config_path: str | Path | None = None) -> None:
        await asyncio.to_thread(self.reload, config_path)

    @property
    def config(self) -> GatewayConfig:
        return self._config

    @property
    def delivery_stats(self) -> DeliveryStats:
        return self._pipeline.events.stats

    def close(self) -> DeliveryStats:
        with self._lock:
            self._closed = True
        return self._pipeline.close()

    async def aclose(self) -> DeliveryStats:
        return await asyncio.to_thread(self.close)

    def __enter__(self) -> Gateway:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    async def __aenter__(self) -> Gateway:
        self._ensure_open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()
