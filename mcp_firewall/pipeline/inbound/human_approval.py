"""Human approval — interactive terminal prompt for tool call approval."""

from __future__ import annotations

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
    """

    stage = PipelineStage.HUMAN_APPROVAL

    def __init__(self, auto_approve: bool = False) -> None:
        self._auto_approve = auto_approve
        self._console = Console(stderr=True)

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        """This is called separately by the pipeline runner when PROMPT is needed."""
        if self._auto_approve:
            return self._allow("Auto-approved")

        return self._prompt_user(request)

    def _prompt_user(self, request: ToolCallRequest) -> PipelineDecision:
        """Show interactive approval prompt."""
        # Only works if stderr is a terminal
        if not sys.stderr.isatty():
            return self._allow("Non-interactive, auto-approved")

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
            self._auto_approve = True
            return self._allow("User approved (always)")
        else:
            return self._deny("User denied", severity=Severity.MEDIUM)
