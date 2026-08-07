"""Dashboard server — runs alongside the proxy."""

from __future__ import annotations

import asyncio
import logging
import threading

import uvicorn

from .app import app, state

logger = logging.getLogger("mcp_firewall.dashboard")


def start_dashboard(host: str = "127.0.0.1", port: int = 9090) -> threading.Thread:
    """Start the dashboard in a background thread."""
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    def _run() -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            # Register the loop so add_event() (called from the proxy thread)
            # can schedule websocket broadcasts on the loop that owns them.
            state.set_loop(loop)
            loop.run_until_complete(server.serve())
        except BaseException as exc:
            # uvicorn calls sys.exit() on startup failure (e.g. port already
            # in use) — catch it so the thread dies with a clear message
            # instead of vanishing silently while the proxy keeps running.
            logger.error(
                "Dashboard server failed (http://%s:%s): %s — proxy continues without dashboard",
                host,
                port,
                exc,
            )
        finally:
            state.set_loop(None)

    thread = threading.Thread(target=_run, daemon=True, name="mcp-firewall-dashboard")
    thread.start()
    return thread
