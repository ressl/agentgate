"""Kill switch — emergency deny-all."""

from __future__ import annotations

import os
import signal
from pathlib import Path

from ..base import InboundStage
from ...models import (
    Action,
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)


class KillSwitch(InboundStage):
    """Emergency kill switch. Denies all requests when activated.

    Activation methods:
    1. File trigger: Create .mcp-firewall-kill in working directory
    2. Signal: Send SIGUSR1 to the process
    3. Programmatic: Set activated = True
    """

    stage = PipelineStage.KILL_SWITCH

    def __init__(self) -> None:
        self.activated = False
        # Register SIGUSR1 handler (Unix only)
        try:
            signal.signal(signal.SIGUSR1, self._signal_handler)
        except (OSError, AttributeError):
            pass  # Windows or restricted environment

    def _signal_handler(self, signum: int, frame: object) -> None:
        self.activated = not self.activated  # Toggle

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.kill_switch.enabled:
            return None

        # Check programmatic activation
        if self.activated:
            return self._deny(
                "Kill switch activated (signal)",
                severity=Severity.CRITICAL,
            )

        # Check file trigger
        kill_file = Path(config.kill_switch.file_path)
        if kill_file.exists():
            return self._deny(
                f"Kill switch activated (file: {kill_file})",
                severity=Severity.CRITICAL,
            )

        return None
