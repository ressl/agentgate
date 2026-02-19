"""Rate limiter — per-agent, per-tool, and global rate limiting."""

from __future__ import annotations

import time
import threading
from collections import defaultdict

from ..base import InboundStage
from ...models import (
    GatewayConfig,
    PipelineDecision,
    PipelineStage,
    Severity,
    ToolCallRequest,
)


class SlidingWindow:
    """Thread-safe sliding window counter."""

    def __init__(self) -> None:
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def add(self, ts: float | None = None) -> None:
        with self._lock:
            self._timestamps.append(ts or time.time())

    def count(self, window_seconds: int) -> int:
        cutoff = time.time() - window_seconds
        with self._lock:
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            return len(self._timestamps)


class RateLimiter(InboundStage):
    """Enforce rate limits: global, per-agent, and per-tool."""

    stage = PipelineStage.RATE_LIMITER

    def __init__(self) -> None:
        self._global = SlidingWindow()
        self._per_agent: dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._per_tool: dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._per_agent_tool: dict[str, SlidingWindow] = defaultdict(SlidingWindow)

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        if not config.rate_limit.enabled:
            return None

        now = time.time()

        # Global rate limit
        if config.rate_limit.max_calls > 0:
            count = self._global.count(config.rate_limit.window_seconds)
            if count >= config.rate_limit.max_calls:
                return self._deny(
                    f"Global rate limit exceeded ({count}/{config.rate_limit.max_calls} "
                    f"in {config.rate_limit.window_seconds}s)",
                    severity=Severity.HIGH,
                )

        # Per-agent rate limit (from agent config)
        agent_cfg = config.agents.get(request.agent_id)
        if agent_cfg and agent_cfg.rate_limit:
            max_calls, window = _parse_rate_limit(agent_cfg.rate_limit)
            if max_calls > 0:
                key = request.agent_id
                count = self._per_agent[key].count(window)
                if count >= max_calls:
                    return self._deny(
                        f"Agent rate limit exceeded for '{request.agent_id}' "
                        f"({count}/{max_calls} in {window}s)",
                        severity=Severity.HIGH,
                    )

        # Per-rule rate limits
        for rule in config.rules:
            if rule.rate_limit and _tool_matches_simple(request.tool_name, rule.tool):
                max_calls = rule.rate_limit.get("maxCalls", rule.rate_limit.get("max_calls", 0))
                window = rule.rate_limit.get("windowSeconds", rule.rate_limit.get("window_seconds", 60))
                if max_calls > 0:
                    key = f"rule:{rule.name}:{request.tool_name}"
                    count = self._per_tool[key].count(window)
                    if count >= max_calls:
                        return self._deny(
                            f"Rule rate limit exceeded for '{rule.name}' "
                            f"({count}/{max_calls} in {window}s)",
                            severity=Severity.MEDIUM,
                        )

        # Record this call
        self._global.add(now)
        if request.agent_id != "unknown":
            self._per_agent[request.agent_id].add(now)

        return None


def _parse_rate_limit(spec: str) -> tuple[int, int]:
    """Parse rate limit spec like '100/min', '50/hour', '10/sec'."""
    try:
        parts = spec.strip().split("/")
        count = int(parts[0])
        unit = parts[1].lower() if len(parts) > 1 else "min"
        windows = {"sec": 1, "s": 1, "min": 60, "m": 60, "hour": 3600, "h": 3600}
        return count, windows.get(unit, 60)
    except (ValueError, IndexError):
        return 0, 60


def _tool_matches_simple(tool_name: str, pattern: str) -> bool:
    """Simple tool matching for rate limit rules."""
    if pattern == "*":
        return True
    return tool_name in pattern.split("|")
