"""Slack alert channel — send alerts to Slack via webhook."""

from __future__ import annotations

import asyncio
import logging

import httpx

from .engine import AlertChannel, AlertEvent
from ..models import Severity

logger = logging.getLogger("mcp_firewall.alerts.slack")

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class SlackChannel(AlertChannel):
    """Send alerts to Slack via incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str, channel: str | None = None) -> None:
        self.webhook_url = webhook_url
        self.channel = channel
        self._client: httpx.AsyncClient | None = None
        self._client_loop: asyncio.AbstractEventLoop | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """Lazily create the shared HTTP client (recreated if closed or the loop changed)."""
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._client_loop is not loop:
            self._client = httpx.AsyncClient(timeout=10)
            self._client_loop = loop
        return self._client

    async def close(self) -> None:
        """Close the shared HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._client_loop = None

    async def send(self, alert: AlertEvent) -> bool:
        emoji = SEVERITY_EMOJI.get(alert.severity, "⚪")
        severity = alert.severity.value.upper()

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} mcp-firewall: {severity} Alert",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{alert.request.tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n`{alert.request.agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Action:*\n{alert.decision.action.value}"},
                    {"type": "mrkdwn", "text": f"*Stage:*\n{alert.decision.stage.value if alert.decision.stage else 'n/a'}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:*\n{alert.decision.reason}",
                },
            },
        ]

        payload: dict = {"blocks": blocks}
        if self.channel:
            payload["channel"] = self.channel

        try:
            resp = await self._get_client().post(self.webhook_url, json=payload)
            return resp.is_success
        except Exception as e:
            logger.error(f"Slack alert failed: {e}")
            return False
