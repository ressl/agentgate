"""Chain detector — detect dangerous multi-tool sequences."""

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

# Dangerous chains: (read_tools, action_tools, description)
DANGEROUS_CHAINS: list[tuple[set[str], set[str], str]] = [
    # Read + Execute = Code injection
    (
        {"read_file", "get_file_contents", "view_file", "cat"},
        {"exec", "shell_exec", "run_command", "execute_command", "bash", "sh"},
        "Read + Execute = Potential code injection",
    ),
    # Read + Send = Data exfiltration
    (
        {"read_file", "get_file_contents", "view_file", "cat", "search", "query"},
        {"http_post", "fetch_url", "fetch", "curl", "wget", "send_request", "http_request"},
        "Read + Send = Potential data exfiltration",
    ),
    # Read + Write = File manipulation
    (
        {"read_file", "get_file_contents"},
        {"write_file", "create_file", "append_file", "overwrite"},
        "Read + Write = Potential file manipulation",
    ),
    # List + Read + Send = Reconnaissance + Exfiltration
    (
        {"list_directory", "list_files", "find", "glob", "search_files"},
        {"http_post", "fetch_url", "send_request", "http_request"},
        "List + Send = Potential reconnaissance and exfiltration",
    ),
    # DB + Send = Database exfiltration
    (
        {"query", "sql", "execute_sql", "db_query", "database_query"},
        {"http_post", "fetch_url", "send_request", "http_request"},
        "DB Query + Send = Potential database exfiltration",
    ),
    # Env/Config + Send = Credential theft
    (
        {"read_file", "get_env", "env", "get_environment"},
        {"http_post", "fetch_url", "send_request"},
        "Config/Env + Send = Potential credential theft",
    ),
]

# Time window for chain detection (seconds)
CHAIN_WINDOW = 300  # 5 minutes


class ChainDetector(InboundStage):
    """Detect dangerous tool call sequences within a time window."""

    stage = PipelineStage.CHAIN_DETECTOR

    def __init__(self) -> None:
        self._history: dict[str, list[tuple[str, float]]] = defaultdict(list)
        self._lock = threading.Lock()

    def evaluate(self, request: ToolCallRequest, config: GatewayConfig) -> PipelineDecision | None:
        now = time.time()
        agent_key = request.agent_id

        with self._lock:
            # Clean old entries
            self._history[agent_key] = [
                (tool, ts) for tool, ts in self._history[agent_key]
                if now - ts < CHAIN_WINDOW
            ]

            # Get recent tool names
            recent_tools = {tool for tool, _ in self._history[agent_key]}
            current_tool = request.tool_name

            # Check for dangerous chains
            for source_tools, target_tools, description in DANGEROUS_CHAINS:
                # Current tool is the dangerous action, and we've seen the source
                if current_tool in target_tools and recent_tools & source_tools:
                    source_match = recent_tools & source_tools
                    self._history[agent_key].append((current_tool, now))
                    return self._deny(
                        f"Dangerous tool chain detected: {description}",
                        severity=Severity.HIGH,
                        details={
                            "chain": list(source_match) + [current_tool],
                            "description": description,
                        },
                    )

            # Record this call
            self._history[agent_key].append((current_tool, now))

        return None

    def reset(self, agent_id: str | None = None) -> None:
        """Clear chain history."""
        with self._lock:
            if agent_id:
                self._history.pop(agent_id, None)
            else:
                self._history.clear()
