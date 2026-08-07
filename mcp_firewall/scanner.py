"""mcpwn integration — pre-deployment security scanning."""

from __future__ import annotations

import importlib.util
import shlex
import subprocess
import sys

# Exit code returned when mcpwn is not installed (distinct from mcpwn's own codes).
SCANNER_NOT_INSTALLED = -1


def run_scan(server_args: list[str], extra_args: list[str] | None = None) -> int:
    """Run mcpwn scan against an MCP server.

    Returns the mcpwn exit code (0=clean, 1=high findings, 2=critical findings),
    or SCANNER_NOT_INSTALLED when mcpwn is not available.
    """
    if importlib.util.find_spec("mcpwn") is None:
        print("Error: mcpwn is not installed.", file=sys.stderr)
        return SCANNER_NOT_INSTALLED

    cmd = [sys.executable, "-m", "mcpwn", "scan", "--stdio", shlex.join(server_args)]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(cmd, capture_output=False)
        return result.returncode
    except FileNotFoundError:
        print("Error: mcpwn is not installed.", file=sys.stderr)
        return SCANNER_NOT_INSTALLED
