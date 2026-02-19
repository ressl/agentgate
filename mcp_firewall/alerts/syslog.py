"""Syslog alert channel — send alerts to syslog (CEF format)."""

from __future__ import annotations

import logging
import logging.handlers
import time

from .engine import AlertChannel, AlertEvent
from ..models import Severity

# CEF severity mapping (0-10)
CEF_SEVERITY = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 5,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


class SyslogChannel(AlertChannel):
    """Send alerts to syslog in CEF (Common Event Format)."""

    name = "syslog"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        facility: int = logging.handlers.SysLogHandler.LOG_LOCAL0,
    ) -> None:
        self.handler = logging.handlers.SysLogHandler(
            address=(host, port),
            facility=facility,
        )

    async def send(self, alert: AlertEvent) -> bool:
        """Format as CEF and send to syslog."""
        cef_severity = CEF_SEVERITY.get(alert.severity, 1)
        stage = alert.decision.stage.value if alert.decision.stage else "unknown"

        # CEF format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
        cef = (
            f"CEF:0|mcp-firewall|mcp-firewall|0.1.0|{stage}|"
            f"{alert.decision.reason[:200]}|{cef_severity}|"
            f"act={alert.decision.action.value} "
            f"src={alert.request.agent_id} "
            f"cs1={alert.request.tool_name} "
            f"cs1Label=ToolName "
            f"rt={int(alert.request.timestamp * 1000)}"
        )

        try:
            record = logging.LogRecord(
                name="mcp-firewall",
                level=logging.WARNING,
                pathname="",
                lineno=0,
                msg=cef,
                args=(),
                exc_info=None,
            )
            self.handler.emit(record)
            return True
        except Exception:
            return False
