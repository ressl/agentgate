"""FastAPI dashboard application."""

from __future__ import annotations

import asyncio
import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from ..models import Action, Severity


class DashboardState:
    """Shared state for the dashboard."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.stats = {
            "total": 0,
            "allowed": 0,
            "denied": 0,
            "redacted": 0,
            "prompted": 0,
        }
        self.by_severity: dict[str, int] = defaultdict(int)
        self.by_tool: dict[str, int] = defaultdict(int)
        self.by_agent: dict[str, int] = defaultdict(int)
        self.by_stage: dict[str, int] = defaultdict(int)
        self._websockets: list[WebSocket] = []
        self._start_time = time.time()

    def add_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        if len(self.events) > 5000:
            self.events = self.events[-2500:]

        self.stats["total"] += 1
        action = event.get("action", "allow")
        if action == "allow":
            self.stats["allowed"] += 1
        elif action == "deny":
            self.stats["denied"] += 1
        elif action == "redact":
            self.stats["redacted"] += 1
        elif action == "prompt":
            self.stats["prompted"] += 1

        self.by_severity[event.get("severity", "info")] += 1
        self.by_tool[event.get("tool", "unknown")] += 1
        self.by_agent[event.get("agent", "unknown")] += 1
        if event.get("stage"):
            self.by_stage[event["stage"]] += 1

        # Broadcast to websockets (best-effort)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._broadcast(event))
        except RuntimeError:
            pass  # No event loop (sync context, tests)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self._websockets:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._websockets.remove(ws)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time


# Global state (shared between proxy and dashboard)
state = DashboardState()

app = FastAPI(title="mcp-firewall Dashboard", docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
async def index():
    return DASHBOARD_HTML


@app.get("/api/stats")
async def api_stats():
    return {
        "stats": state.stats,
        "by_severity": dict(state.by_severity),
        "by_tool": dict(state.by_tool),
        "by_agent": dict(state.by_agent),
        "by_stage": dict(state.by_stage),
        "uptime": int(state.uptime_seconds),
        "events_buffered": len(state.events),
    }


@app.get("/api/events")
async def api_events(limit: int = 50):
    return state.events[-limit:]


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state._websockets.append(websocket)
    try:
        # Send recent events on connect
        for event in state.events[-20:]:
            await websocket.send_json(event)
        # Keep alive
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in state._websockets:
            state._websockets.remove(websocket)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcp-firewall Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff; --orange: #db6d28;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; }
  .header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 18px; font-weight: 600; }
  .header .badge { font-size: 12px; padding: 2px 8px; border-radius: 12px; background: var(--blue); color: var(--bg); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; padding: 16px 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .label { font-size: 12px; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .card .value.green { color: var(--green); }
  .card .value.red { color: var(--red); }
  .card .value.yellow { color: var(--yellow); }
  .card .value.blue { color: var(--blue); }
  .feed { padding: 0 24px 24px; }
  .feed h2 { font-size: 14px; color: var(--dim); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .event-list { max-height: 60vh; overflow-y: auto; }
  .event { display: flex; gap: 12px; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; align-items: flex-start; }
  .event:hover { background: var(--surface); }
  .event .time { color: var(--dim); white-space: nowrap; font-family: monospace; min-width: 80px; }
  .event .sev { min-width: 20px; text-align: center; }
  .event .tool { color: var(--blue); min-width: 120px; font-family: monospace; }
  .event .agent { color: var(--dim); min-width: 100px; }
  .event .reason { flex: 1; }
  .event .action-allow { color: var(--green); }
  .event .action-deny { color: var(--red); }
  .event .action-redact { color: var(--yellow); }
  .event .action-prompt { color: var(--orange); }
  .connected { width: 8px; height: 8px; border-radius: 50%; background: var(--green); display: inline-block; }
  .disconnected { width: 8px; height: 8px; border-radius: 50%; background: var(--red); display: inline-block; }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ mcp-firewall</h1>
  <span class="badge">LIVE</span>
  <span id="ws-status" class="connected"></span>
</div>

<div class="grid">
  <div class="card"><div class="label">Total Calls</div><div class="value blue" id="stat-total">0</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value green" id="stat-allowed">0</div></div>
  <div class="card"><div class="label">Denied</div><div class="value red" id="stat-denied">0</div></div>
  <div class="card"><div class="label">Redacted</div><div class="value yellow" id="stat-redacted">0</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="stat-uptime">0s</div></div>
</div>

<div class="feed">
  <h2>Live Event Feed</h2>
  <div class="event-list" id="events"></div>
</div>

<script>
const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
const stats = { total: 0, allowed: 0, denied: 0, redacted: 0 };
let startTime = Date.now();

function updateStats() {
  document.getElementById('stat-total').textContent = stats.total;
  document.getElementById('stat-allowed').textContent = stats.allowed;
  document.getElementById('stat-denied').textContent = stats.denied;
  document.getElementById('stat-redacted').textContent = stats.redacted;
}

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

function addEvent(evt) {
  const el = document.getElementById('events');
  const div = document.createElement('div');
  div.className = 'event';
  const actionClass = 'action-' + (evt.action || 'allow');
  div.innerHTML = `
    <span class="time">${formatTime(evt.timestamp || Date.now()/1000)}</span>
    <span class="sev">${sevEmoji[evt.severity] || '⚪'}</span>
    <span class="tool">${evt.tool || 'n/a'}</span>
    <span class="agent">${evt.agent || 'unknown'}</span>
    <span class="${actionClass}">${(evt.action || 'allow').toUpperCase()}</span>
    <span class="reason">${evt.reason || ''}</span>
  `;
  el.insertBefore(div, el.firstChild);
  if (el.children.length > 200) el.removeChild(el.lastChild);

  stats.total++;
  if (evt.action === 'deny') stats.denied++;
  else if (evt.action === 'redact') stats.redacted++;
  else stats.allowed++;
  updateStats();
}

function connectWS() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => { document.getElementById('ws-status').className = 'connected'; };
  ws.onclose = () => { document.getElementById('ws-status').className = 'disconnected'; setTimeout(connectWS, 2000); };
  ws.onmessage = (e) => { addEvent(JSON.parse(e.data)); };
}

// Load initial stats
fetch('/api/stats').then(r => r.json()).then(data => {
  Object.assign(stats, data.stats);
  startTime = Date.now() - (data.uptime * 1000);
  updateStats();
});

// Load recent events
fetch('/api/events?limit=50').then(r => r.json()).then(events => {
  events.forEach(addEvent);
});

// Update uptime
setInterval(() => {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  document.getElementById('stat-uptime').textContent = h > 0 ? `${h}h ${m}m` : `${m}m ${s%60}s`;
}, 1000);

connectWS();
</script>
</body>
</html>"""
