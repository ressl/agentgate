"""FastAPI dashboard application."""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response

from ..models import EventPhase, SecurityEvent
from .approval_ui import APPROVAL_HTML, APPROVAL_SCRIPT
from .approvals import router as approval_router
from .event_feed import record_integration_event

# Cap for the by_* aggregation dicts: tool and agent names are
# attacker-controlled, so the number of distinct keys must stay bounded.
MAX_AGG_KEYS = 1000


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
            "responses_denied": 0,
        }
        self.by_severity: dict[str, int] = defaultdict(int)
        self.by_tool: dict[str, int] = defaultdict(int)
        self.by_agent: dict[str, int] = defaultdict(int)
        self.by_stage: dict[str, int] = defaultdict(int)
        self._websockets: list[WebSocket] = []
        self._start_time = time.time()
        # Guards all mutable state above; add_event() is called from the
        # proxy thread while the uvicorn loop reads/writes it in its own.
        self._lock = threading.Lock()
        # Event loop the dashboard server runs on (set by server.py).
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop | None) -> None:
        """Register the event loop the dashboard server runs on."""
        with self._lock:
            self._loop = loop

    @staticmethod
    def _bump(counter: dict[str, int], key: str) -> None:
        if key in counter or len(counter) < MAX_AGG_KEYS:
            counter[key] += 1
        else:
            counter["other"] += 1

    def add_security_event(self, event: SecurityEvent) -> None:
        """Display final decisions without counting lifecycle observations as calls."""
        record_integration_event(event)
        if event.phase not in {
            EventPhase.REQUEST_ALLOWED,
            EventPhase.REQUEST_DENIED,
            EventPhase.RESPONSE_REDACTED,
            EventPhase.RESPONSE_DENIED,
        }:
            return
        payload = event.model_dump(mode="json")
        payload["direction"] = (
            "outbound"
            if event.phase
            in {
                EventPhase.RESPONSE_REDACTED,
                EventPhase.RESPONSE_DENIED,
            }
            else "inbound"
        )
        self.add_event(payload)

    def add_event(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)
            if len(self.events) > 5000:
                self.events = self.events[-2500:]

            outbound = event.get("direction") == "outbound"
            if not outbound:
                self.stats["total"] += 1
            action = event.get("action", "allow")
            if action == "allow":
                if not outbound:
                    self.stats["allowed"] += 1
            elif action == "deny":
                self.stats["responses_denied" if outbound else "denied"] += 1
            elif action == "redact":
                self.stats["redacted"] += 1
            elif action == "prompt":
                self.stats["prompted"] += 1

            self._bump(self.by_severity, event.get("severity", "info"))
            if not outbound:
                self._bump(self.by_tool, event.get("tool", "unknown"))
            self._bump(self.by_agent, event.get("agent", "unknown"))
            if event.get("stage"):
                self._bump(self.by_stage, event["stage"])

            loop = self._loop

        # Broadcast to websockets (best-effort). The websockets belong to the
        # uvicorn loop, so the broadcast must be scheduled there — never via
        # create_task on the caller's (proxy) loop.
        if loop is not None:
            try:
                loop.call_soon_threadsafe(loop.create_task, self._broadcast(event))
            except RuntimeError:
                pass  # Loop closed
        else:
            try:
                running = asyncio.get_running_loop()
                running.create_task(self._broadcast(event))
            except RuntimeError:
                pass  # No event loop (sync context, tests)

    async def _broadcast(self, event: dict[str, Any]) -> None:
        with self._lock:
            targets = list(self._websockets)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        with self._lock:
            for ws in dead:
                if ws in self._websockets:
                    self._websockets.remove(ws)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time


# Global state (shared between proxy and dashboard)
state = DashboardState()

app = FastAPI(title="mcp-firewall Dashboard", docs_url=None, redoc_url=None)
app.include_router(approval_router)


@app.middleware("http")
async def security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if (
        request.url.path.startswith("/api/approval")
        or request.url.path == "/api/integration-events"
    ):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return DASHBOARD_HTML


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    with state._lock:
        return {
            "stats": dict(state.stats),
            "by_severity": dict(state.by_severity),
            "by_tool": dict(state.by_tool),
            "by_agent": dict(state.by_agent),
            "by_stage": dict(state.by_stage),
            "uptime": int(state.uptime_seconds),
            "events_buffered": len(state.events),
        }


@app.get("/api/events")
async def api_events(limit: int = Query(50, ge=1, le=1000)) -> list[dict[str, Any]]:
    with state._lock:
        events = list(state.events[-limit:])
    # Tag replays so the client does not count them against the live stats.
    return [dict(event, replay=True) for event in events]


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    with state._lock:
        state._websockets.append(websocket)
        replay = [dict(event, replay=True) for event in state.events[-20:]]
    try:
        # Send recent events on connect
        for event in replay:
            await websocket.send_json(event)
        # Keep alive
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        with state._lock:
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
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --dim: #8b949e;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #d29922;
    --blue: #58a6ff;
    --orange: #db6d28;
  }
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
  }
  .header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .header h1 {
    font-size: 18px;
    font-weight: 600;
  }
  .header .badge {
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 12px;
    background: var(--blue);
    color: var(--bg);
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    padding: 16px 24px;
  }
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .card .label {
    font-size: 12px;
    color: var(--dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .card .value {
    font-size: 28px;
    font-weight: 700;
    margin-top: 4px;
  }
  .card .value.green {
    color: var(--green);
  }
  .card .value.red {
    color: var(--red);
  }
  .card .value.yellow {
    color: var(--yellow);
  }
  .card .value.blue {
    color: var(--blue);
  }
  .feed {
    padding: 0 24px 24px;
  }
  .feed h2 {
    font-size: 14px;
    color: var(--dim);
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .event-list {
    max-height: 60vh;
    overflow-y: auto;
  }
  .event {
    display: flex;
    gap: 12px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    align-items: flex-start;
  }
  .event:hover {
    background: var(--surface);
  }
  .event .time {
    color: var(--dim);
    white-space: nowrap;
    font-family: monospace;
    min-width: 80px;
  }
  .event .sev {
    min-width: 20px;
    text-align: center;
  }
  .event .tool {
    color: var(--blue);
    min-width: 120px;
    font-family: monospace;
  }
  .event .agent {
    color: var(--dim);
    min-width: 100px;
  }
  .event .reason {
    flex: 1;
  }
  .event .action-allow {
    color: var(--green);
  }
  .event .action-deny {
    color: var(--red);
  }
  .event .action-redact {
    color: var(--yellow);
  }
  .event .action-prompt {
    color: var(--orange);
  }
  .connected {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    display: inline-block;
  }
  .disconnected {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--red);
    display: inline-block;
  }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ mcp-firewall</h1>
  <span class="badge">LIVE</span>
  <span id="ws-status" class="connected"></span>
</div>
<div class="grid">
  <div class="card">
    <div class="label">Total Calls</div>
    <div class="value blue" id="stat-total">0</div>
  </div>
  <div class="card">
    <div class="label">Allowed</div>
    <div class="value green" id="stat-allowed">0</div>
  </div>
  <div class="card">
    <div class="label">Denied</div>
    <div class="value red" id="stat-denied">0</div>
  </div>
  <div class="card">
    <div class="label">Redacted</div>
    <div class="value yellow" id="stat-redacted">0</div>
  </div>
  <div class="card">
    <div class="label">Responses blocked</div>
    <div class="value red" id="stat-responses-denied">0</div>
  </div>
  <div class="card">
    <div class="label">Uptime</div>
    <div class="value " id="stat-uptime">0</div>
  </div>
</div>
<!-- APPROVAL_CONTROLS -->
<div class="feed">
  <h2>Live Event Feed</h2>
  <div class="event-list" id="events"></div>
</div>

<script>
const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
const stats = { total: 0, allowed: 0, denied: 0, redacted: 0, responses_denied: 0 };
let startTime = Date.now();

function updateStats() {
  document.getElementById('stat-total').textContent = stats.total;
  document.getElementById('stat-allowed').textContent = stats.allowed;
  document.getElementById('stat-denied').textContent = stats.denied;
  document.getElementById('stat-redacted').textContent = stats.redacted;
  document.getElementById('stat-responses-denied').textContent = stats.responses_denied;
}

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

function addEvent(evt) {
  const el = document.getElementById('events');
  const div = document.createElement('div');
  div.className = 'event';
  const action = evt.action || 'allow';
  // Build cells via textContent — tool/agent/reason are attacker-controlled
  // and must never be interpolated into innerHTML.
  const cells = [
    ['time', formatTime(evt.timestamp || Date.now()/1000)],
    ['sev', sevEmoji[evt.severity] || '⚪'],
    ['tool', evt.tool || 'n/a'],
    ['agent', evt.agent || 'unknown'],
    ['action-' + action, action.toUpperCase()],
    ['reason', evt.reason || ''],
  ];
  for (const [cls, text] of cells) {
    const span = document.createElement('span');
    span.className = cls;
    span.textContent = text;
    div.appendChild(span);
  }
  el.insertBefore(div, el.firstChild);
  if (el.children.length > 200) el.removeChild(el.lastChild);

  // Server stats are the source of truth; only count live events locally,
  // never replays (REST/WS history) — those are already in the server stats.
  if (!evt.replay) {
    if (evt.direction !== 'outbound') {
      stats.total++;
      if (action === 'deny') stats.denied++;
      else if (action !== 'redact') stats.allowed++;
    }
    if (action === 'redact') stats.redacted++;
    if (evt.direction === 'outbound' && action === 'deny') stats.responses_denied++;
    updateStats();
  }
}

function connectWS() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => { document.getElementById('ws-status').className = 'connected';
  };
  ws.onclose = () => { document.getElementById('ws-status').className = 'disconnected';
  setTimeout(connectWS, 2000);
  };
  ws.onmessage = (e) => { addEvent(JSON.parse(e.data));
  };
}

// Load initial stats
fetch('/api/stats').then(r => r.json()).then(data => {
  Object.assign(stats, data.stats);
  startTime = Date.now() - (data.uptime * 1000);
  updateStats();
});

// Load recent events (replay — renders without touching the counters)
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

DASHBOARD_HTML = DASHBOARD_HTML.replace("<!-- APPROVAL_CONTROLS -->", APPROVAL_HTML).replace(
    "</body>", APPROVAL_SCRIPT + "</body>"
)
