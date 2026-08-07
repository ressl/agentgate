"""Human approval — interactive terminal prompt for tool call approval."""

from __future__ import annotations

import asyncio
import json
import sys

from rich.console import Console
from rich.panel import Panel

from ..base import InboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)


class HumanApproval(InboundStage):
    """Prompt the user in the terminal for tool call approval.

    This stage runs AFTER the policy engine and only fires when a previous
    stage returned Action.PROMPT.

    Non-interactive sessions fail closed (DENY) unless ``allow_non_interactive``
    is set. In proxy mode stdin carries the JSON-RPC protocol, so interactive
    prompts are impossible there — pass ``stdin_available=False``.
    """

    stage = PipelineStage.HUMAN_APPROVAL

    def __init__(
        self,
        auto_approve: bool = False,
        allow_non_interactive: bool = False,
        stdin_available: bool = True,
    ) -> None:
        self._auto_approve = auto_approve
        self._allow_non_interactive = allow_non_interactive
        self._stdin_available = stdin_available
        # "always" approvals are scoped to (agent, tool), not global
        self._always_approved: set[tuple[str, str]] = set()
        self._console = Console(stderr=True)

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        """Synchronous evaluation (SDK / non-async callers)."""
        decision = self._pre_approved(request)
        if decision is not None:
            return decision

        if not self._can_prompt():
            return self._non_interactive_fallback()

        return self._prompt_user(request)

    async def aevaluate(
        self, request: ToolCallRequest, config: GatewayConfig
    ) -> PipelineDecision | None:
        """Async evaluation — the blocking prompt runs off the event loop."""
        decision = self._pre_approved(request)
        if decision is not None:
            return decision

        if not self._can_prompt():
            return self._non_interactive_fallback()

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._prompt_user, request)

    def _pre_approved(self, request: ToolCallRequest) -> PipelineDecision | None:
        if self._auto_approve:
            return self._allow("Auto-approved")
        if (request.agent_id, request.tool_name) in self._always_approved:
            return self._allow("User approved (always)")
        return None

    def _can_prompt(self) -> bool:
        # Interactive approval needs a real terminal on stdin — and stdin must
        # not be the MCP protocol channel (proxy mode).
        return self._stdin_available and sys.stdin.isatty()

    def _non_interactive_fallback(self) -> PipelineDecision:
        if self._allow_non_interactive:
            return self._allow("Non-interactive, auto-approved")
        return self._deny(
            "Non-interactive session, approval not possible",
            severity=Severity.MEDIUM,
        )

    def _prompt_user(self, request: ToolCallRequest) -> PipelineDecision:
        """Show interactive approval prompt (blocking — keep off the event loop)."""
        args_str = json.dumps(request.arguments, indent=2)
        if len(args_str) > 500:
            args_str = args_str[:500] + "\n  ... (truncated)"

        self._console.print()
        self._console.print(Panel(
            f"[bold yellow]Tool Call Approval Required[/bold yellow]\n\n"
            f"[bold]Agent:[/bold] {request.agent_id}\n"
            f"[bold]Tool:[/bold]  {request.tool_name}\n"
            f"[bold]Args:[/bold]\n{args_str}",
            border_style="yellow",
            expand=False,
        ))

        try:
            self._console.print("  [yellow]Allow this call? [y/N/always]:[/yellow] ", end="")
            response = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            response = "n"

        if response in ("y", "yes"):
            return self._allow("User approved")
        elif response in ("always", "a"):
            self._always_approved.add((request.agent_id, request.tool_name))
            return self._allow("User approved (always)")
        else:
            return self._deny("User denied", severity=Severity.MEDIUM)
