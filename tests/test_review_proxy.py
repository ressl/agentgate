"""Tests for code-review fixes: proxy, human approval, kill switch, runner.

Covers findings H1-H4, M4, M6 (proxy buffer), M10, M12, M14, L1, L2, L12
from docs/code-review-2026-08.md.
"""

from __future__ import annotations

import asyncio
import json
import signal
import threading
from types import SimpleNamespace

import pytest

from mcp_firewall.models import (
    Action,
    AgentConfig,
    GatewayConfig,
    RuleConfig,
    ToolCallRequest,
    ToolCallResponse,
)
from mcp_firewall.pipeline.inbound.human_approval import HumanApproval
from mcp_firewall.pipeline.inbound.kill_switch import KillSwitch
from mcp_firewall.pipeline.runner import PipelineRunner
from mcp_firewall.proxy.stdio import MAX_MESSAGE_SIZE, StdioProxy


def make_config(**kwargs) -> GatewayConfig:
    config = GatewayConfig(**kwargs)
    config.audit.enabled = False
    config.rate_limit.max_calls = 10000
    return config


def make_request(tool: str = "read_file", args: dict | None = None, agent: str = "unknown"):
    return ToolCallRequest(tool_name=tool, arguments=args or {}, agent_id=agent)


def make_proxy(config: GatewayConfig | None = None) -> StdioProxy:
    return StdioProxy(config or make_config())


# --- H1: non-interactive approval fails closed ---

class TestNonInteractiveApproval:
    def test_non_interactive_denies_by_default(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        ha = HumanApproval()
        result = ha.evaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.DENY

    def test_non_interactive_allow_is_configurable(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        ha = HumanApproval(allow_non_interactive=True)
        result = ha.evaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.ALLOW

    def test_stdin_protocol_channel_denies(self, monkeypatch):
        # Proxy mode: stdin is a TTY but carries the JSON-RPC protocol
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        ha = HumanApproval(stdin_available=False)
        result = ha.evaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.DENY


# --- H2: approval runs off the event loop ---

class TestAsyncApproval:
    async def test_aevaluate_non_interactive_denies(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        ha = HumanApproval()
        result = await ha.aevaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.DENY

    async def test_aevaluate_prompts_in_executor(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("builtins.input", lambda: "y")
        ha = HumanApproval()
        result = await ha.aevaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.ALLOW

    async def test_aevaluate_auto_approve(self):
        ha = HumanApproval(auto_approve=True)
        result = await ha.aevaluate(make_request(), make_config())
        assert result is not None
        assert result.action == Action.ALLOW


# --- M14: "always" is scoped per (agent, tool) ---

class TestAlwaysScoping:
    def test_always_applies_to_same_tool_only(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["always", "n"])
        monkeypatch.setattr("builtins.input", lambda: next(answers))
        ha = HumanApproval()
        config = make_config()

        first = ha.evaluate(make_request(tool="exec", agent="bot"), config)
        assert first.action == Action.ALLOW

        # Same tool + agent: approved without prompting again
        again = ha.evaluate(make_request(tool="exec", agent="bot"), config)
        assert again.action == Action.ALLOW

        # Different tool: prompts again (second answer "n" -> deny)
        other = ha.evaluate(make_request(tool="write_file", agent="bot"), config)
        assert other.action == Action.DENY

    def test_always_does_not_leak_across_agents(self, monkeypatch):
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["always", "n"])
        monkeypatch.setattr("builtins.input", lambda: next(answers))
        ha = HumanApproval()
        config = make_config()

        ha.evaluate(make_request(tool="exec", agent="bot-a"), config)
        # Different agent, same tool: prompts again
        result = ha.evaluate(make_request(tool="exec", agent="bot-b"), config)
        assert result.action == Action.DENY


# --- M12: KillSwitch signal registration ---

class TestKillSwitchSignals:
    def test_works_outside_main_thread(self):
        errors = []

        def create():
            try:
                KillSwitch()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        t = threading.Thread(target=create)
        t.start()
        t.join()
        assert errors == []

    def test_does_not_clobber_existing_handler(self):
        def existing(signum, frame):
            pass

        if not hasattr(signal, "SIGUSR1"):
            pytest.skip("SIGUSR1 not available")
        previous = signal.getsignal(signal.SIGUSR1)
        signal.signal(signal.SIGUSR1, existing)
        try:
            KillSwitch()
            assert signal.getsignal(signal.SIGUSR1) is existing
        finally:
            signal.signal(signal.SIGUSR1, previous)


# --- L1/L2: runner audit behavior ---

class TestRunnerAudit:
    def test_approval_logged_once(self, tmp_path):
        config = make_config(default_action=Action.PROMPT)
        config.audit.enabled = True
        config.audit.path = str(tmp_path / "audit.jsonl")
        runner = PipelineRunner(config, auto_approve=True)

        decision = runner.evaluate_inbound(make_request())
        assert decision is None  # approved -> allowed

        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["stage"] == "human_approval"
        assert entry["decision"] == "allow"

    def test_outbound_decisions_audited(self, tmp_path):
        config = make_config()
        config.audit.enabled = True
        config.audit.path = str(tmp_path / "audit.jsonl")
        runner = PipelineRunner(config)

        resp = ToolCallResponse(
            request_id="1",
            content=[{"type": "text", "text": "Key: AKIAIOSFODNN7EXAMPLE"}],
        )
        _, decisions = runner.scan_outbound(make_request(), resp)
        assert decisions

        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        assert len(lines) == len(decisions)
        assert json.loads(lines[0])["decision"] == "redact"


# --- H3: proxy robustness on malformed messages ---

class TestProxyRobustness:
    async def test_non_dict_json_dropped(self, capsys):
        proxy = make_proxy()
        assert await proxy._intercept_request(b"123") is None
        assert await proxy._intercept_request(b'"just a string"') is None
        assert await proxy._intercept_request(b"[1, 2]") is None

    async def test_non_json_passes_through(self):
        proxy = make_proxy()
        assert await proxy._intercept_request(b"not json at all") == b"not json at all"

    async def test_invalid_tool_call_sends_error(self, capsys):
        proxy = make_proxy()
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "exec", "arguments": [1, 2, 3]},
        }).encode()
        assert await proxy._intercept_request(raw) is None
        out = capsys.readouterr().out
        assert '"error"' in out
        assert '"code": -32602' in out

    async def test_invalid_tool_call_notification_no_response(self, capsys):
        proxy = make_proxy()
        raw = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "exec", "arguments": [1, 2, 3]},
        }).encode()
        assert await proxy._intercept_request(raw) is None
        assert capsys.readouterr().out == ""

    async def test_non_dict_response_passes_through(self):
        proxy = make_proxy()
        assert await proxy._intercept_response(b"42") == b"42"


# --- H4: agent identity from initialize handshake ---

class TestAgentIdentity:
    async def test_initialize_sets_agent_id(self):
        config = make_config(default_action=Action.ALLOW)
        proxy = make_proxy(config)

        init = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"clientInfo": {"name": "claude-code", "version": "1.0"}},
        }).encode()
        # initialize is forwarded, not intercepted
        assert await proxy._intercept_request(init) == init
        assert proxy._agent_id == "claude-code"

    async def test_agent_rbac_fires(self, capsys):
        config = make_config(default_action=Action.ALLOW)
        config.agents["evil-bot"] = AgentConfig(deny=["exec"])
        proxy = make_proxy(config)

        await proxy._intercept_request(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"clientInfo": {"name": "evil-bot"}},
        }).encode())

        raw = json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "exec", "arguments": {"cmd": "ls"}},
        }).encode()
        assert await proxy._intercept_request(raw) is None
        out = capsys.readouterr().out
        assert '"error"' in out
        assert "evil-bot" in out

    async def test_agent_id_fallback_unknown(self):
        proxy = make_proxy()
        assert proxy._agent_id == "unknown"


# --- L12: denied calls use JSON-RPC error objects; notifications get none ---

class TestDenyResponses:
    async def test_denied_call_returns_error_object(self, capsys):
        config = make_config(default_action=Action.ALLOW)
        config.rules = [RuleConfig(name="no-exec", tool="exec", action=Action.DENY)]
        proxy = make_proxy(config)

        raw = json.dumps({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "exec", "arguments": {}},
        }).encode()
        assert await proxy._intercept_request(raw) is None
        out = capsys.readouterr().out
        response = json.loads(out.strip())
        assert response["id"] == 5
        assert "error" in response
        assert "result" not in response
        assert "Blocked" in response["error"]["message"]

    async def test_denied_notification_gets_no_response(self, capsys):
        config = make_config(default_action=Action.ALLOW)
        config.rules = [RuleConfig(name="no-exec", tool="exec", action=Action.DENY)]
        proxy = make_proxy(config)

        raw = json.dumps({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "exec", "arguments": {}},
        }).encode()
        assert await proxy._intercept_request(raw) is None
        assert capsys.readouterr().out == ""


# --- M4: outbound DENY wins over earlier REDACT ---

class TestOutboundEnforcement:
    async def test_deny_wins_over_redact(self):
        config = make_config()
        config.pii.enabled = True
        config.pii.action = Action.DENY
        proxy = make_proxy(config)

        # SecretScanner (REDACT) runs before PIIDetector (DENY)
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 9,
            "result": {
                "content": [{
                    "type": "text",
                    "text": "Key: AKIAIOSFODNN7EXAMPLE Email: test@test.com",
                }],
            },
        }).encode()
        out = json.loads((await proxy._intercept_response(raw)).decode())
        assert out["result"]["isError"] is True
        assert "Response blocked" in out["result"]["content"][0]["text"]
        assert "AKIAIOSFODNN7EXAMPLE" not in out["result"]["content"][0]["text"]

    async def test_redact_applied_when_no_deny(self):
        proxy = make_proxy()
        raw = json.dumps({
            "jsonrpc": "2.0", "id": 9,
            "result": {
                "content": [{"type": "text", "text": "Key: AKIAIOSFODNN7EXAMPLE"}],
            },
        }).encode()
        out = json.loads((await proxy._intercept_response(raw)).decode())
        assert "[REDACTED" in out["result"]["content"][0]["text"]


# --- M6: read buffer size limit ---

class TestBufferLimit:
    async def test_oversized_server_message_closes_loop(self):
        proxy = make_proxy()
        reader = asyncio.StreamReader()
        # No newline, no EOF: unlimited buffer would wait/grow forever
        reader.feed_data(b"x" * (MAX_MESSAGE_SIZE + 1))
        proxy._server_proc = SimpleNamespace(stdout=reader)

        await asyncio.wait_for(proxy._proxy_server_to_client(), timeout=5.0)


# --- M10: exit code mapping ---

class TestExitCode:
    def test_sigterm_is_clean_exit(self):
        assert StdioProxy._exit_code(-signal.SIGTERM) == 0

    def test_none_is_clean_exit(self):
        assert StdioProxy._exit_code(None) == 0

    def test_real_exit_codes_propagate(self):
        assert StdioProxy._exit_code(0) == 0
        assert StdioProxy._exit_code(3) == 3
