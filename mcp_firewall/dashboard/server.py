"""Dashboard server — runs alongside the proxy."""

from __future__ import annotations

import threading

import uvicorn

from .app import app


def start_dashboard(host: str = "127.0.0.1", port: int = 9090) -> threading.Thread:
    """Start the dashboard in a background thread."""
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True, name="mcp-firewall-dashboard")
    thread.start()
    return thread
