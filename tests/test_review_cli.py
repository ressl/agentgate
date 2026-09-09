"""Tests for code-review fixes in cli.py and scanner.py (M9, M13, L11, L14, L15)."""

from __future__ import annotations

import importlib.util
import shlex
import sys

import pytest
from click.testing import CliRunner

from mcp_firewall import scanner
from mcp_firewall.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# --- M9: wrap --config must reject nonexistent paths -------------------------


def test_wrap_config_must_exist(runner: CliRunner, tmp_path) -> None:
    result = runner.invoke(main, ["wrap", "--config", str(tmp_path / "typo.yaml"), "--", "echo"])
    assert result.exit_code != 0
    assert "does not exist" in result.output


# --- L11: init --enterprise generates a stricter config -----------------------


def test_init_default_config(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        content = open("mcp-firewall.yaml").read()
        assert "defaultAction: prompt" in content


def test_init_enterprise_config(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--enterprise"])
        assert result.exit_code == 0
        content = open("mcp-firewall.yaml").read()
        assert "defaultAction: deny" in content
        assert "sensitivity: high" in content
        assert "detectPII: true" in content
        assert "maxCalls: 60" in content


def test_init_enterprise_config_validates(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        assert runner.invoke(main, ["init", "--enterprise"]).exit_code == 0
        result = runner.invoke(main, ["validate"])
        assert result.exit_code == 0, result.output
        assert "deny" in result.output


# --- L14: audit reports an error when the log file is missing ----------------


def test_audit_missing_log_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["audit"])
        assert result.exit_code == 1
        assert "not found" in result.output


def test_audit_existing_log_file(runner: CliRunner) -> None:
    with runner.isolated_filesystem():
        open("mcp-firewall.audit.jsonl", "w").close()
        result = runner.invoke(main, ["audit"])
        assert result.exit_code == 0, result.output
        assert "integrity verified" in result.output


# --- L15: dashboard host/port are configurable --------------------------------


def test_wrap_dashboard_options_in_help(runner: CliRunner) -> None:
    result = runner.invoke(main, ["wrap", "--help"])
    assert result.exit_code == 0
    assert "--dashboard-host" in result.output
    assert "--dashboard-port" in result.output


def test_wrap_dashboard_host_port_passed_through(runner: CliRunner, monkeypatch) -> None:
    started: dict = {}

    def fake_start_dashboard(host: str = "127.0.0.1", port: int = 9090):
        started["host"] = host
        started["port"] = port

    class FakeProxy:
        def __init__(self, config, console):
            pass

        async def run(self, args) -> int:
            return 0

    monkeypatch.setattr("mcp_firewall.dashboard.server.start_dashboard", fake_start_dashboard)
    monkeypatch.setattr("mcp_firewall.proxy.stdio.StdioProxy", FakeProxy)

    result = runner.invoke(
        main,
        [
            "wrap",
            "--dashboard",
            "--dashboard-host",
            "0.0.0.0",  # noqa: S104 - mocked bind; no socket opened
            "--dashboard-port",
            "9999",
            "--",
            "echo",
        ],
    )
    assert result.exit_code == 0, result.output
    assert started == {"host": "0.0.0.0", "port": 9999}  # noqa: S104 - mocked bind; no socket opened
    assert "http://0.0.0.0:9999" in result.output


# --- M13: scanner handles missing mcpwn and preserves quoting -----------------


def test_run_scan_missing_mcpwn(monkeypatch, capsys) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert scanner.run_scan(["python", "server.py"]) == scanner.SCANNER_NOT_INSTALLED
    assert "mcpwn" in capsys.readouterr().err


def test_run_scan_preserves_quoting(monkeypatch) -> None:
    captured: dict = {}

    def fake_run(cmd, capture_output=False):
        captured["cmd"] = cmd

        class Result:
            returncode = 0

        return Result()

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    args = ["python", "my server.py", "--path", "/tmp/with space"]  # noqa: S108 - inert path fixture; no temporary I/O
    assert scanner.run_scan(args, ["--format", "json"]) == 0

    cmd = captured["cmd"]
    assert cmd[:4] == [sys.executable, "-m", "mcpwn", "scan"]
    assert cmd[4] == "--stdio"
    assert cmd[5] == shlex.join(args)
    assert cmd[6:] == ["--format", "json"]


def test_scan_command_missing_mcpwn(runner: CliRunner, monkeypatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    result = runner.invoke(main, ["scan", "--", "python", "server.py"])
    assert result.exit_code == 3
    assert "pip install mcpwn" in result.output


def test_scan_command_passes_through_exit_code(runner: CliRunner, monkeypatch) -> None:
    monkeypatch.setattr("mcp_firewall.scanner.run_scan", lambda args, extra: 2)
    result = runner.invoke(main, ["scan", "--", "python", "server.py"])
    assert result.exit_code == 2
