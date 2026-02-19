"""Webhook alert channel — send alerts to any HTTP endpoint."""

from __future__ import annotations

import json
import logging

import httpx

from .engine import AlertChannel, AlertEvent

logger = logging.getLogger("mcp_firewall.alerts.webhook")


class WebhookChannel(AlertChannel):
    """Send alerts as JSON POST to a webhook URL."""

    name = "webhook"

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    async def send(self, alert: AlertEvent) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.url,
                    json={
                        "source": "mcp-firewall",
                        "alert": alert.to_dict(),
                    },
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "mcp-firewall/0.1.0",
                        **self.headers,
                    },
                )
                return resp.is_success
        except Exception as e:
            logger.error(f"Webhook alert failed: {e}")
            return False
