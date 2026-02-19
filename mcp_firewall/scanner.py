"""mcpwn integration — pre-deployment security scanning."""

from __future__ import annotations

import subprocess
import sys


def run_scan(server_args: list[str], extra_args: list[str] | None = None) -> int:
    """Run mcpwn scan against an MCP server.

    Returns the mcpwn exit code (0=clean, 1=high findings, 2=critical findings).
    """
    cmd = [sys.executable, "-m", "mcpwn", "scan", "--stdio", " ".join(server_args)]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=False)
        return result.returncode
    except FileNotFoundError:
        print("Error: mcpwn not installed. Install with: pip install mcpwn")
        return -1
