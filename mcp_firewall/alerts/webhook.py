"""Webhook alert channel — send alerts to any HTTP endpoint."""

from __future__ import annotations

import asyncio
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
        try:
            resp = await self._get_client().post(
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
