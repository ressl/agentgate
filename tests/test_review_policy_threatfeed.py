"""Tests for code-review fixes: glob escaping (H6), rate-limit globs (M3),
bounded maps (M6), non-string argument values (L7)."""

from __future__ import annotations

import logging

from mcp_firewall.models import (
    Action,
    GatewayConfig,
    RuleConfig,
    Severity,
    ToolCallRequest,
)
from mcp_firewall.pipeline.inbound import chain_detector, rate_limiter
from mcp_firewall.pipeline.inbound.chain_detector import ChainDetector
from mcp_firewall.pipeline.inbound.policy import PolicyEngine, _arguments_match
from mcp_firewall.pipeline.inbound.rate_limiter import RateLimiter, _tool_matches_simple
from mcp_firewall.threatfeed.loader import ThreatRule


def make_request(
    tool: str = "read_file", args: dict | None = None, agent: str = "test-agent"
) -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, arguments=args or {}, agent_id=agent)


def make_rule(**kwargs) -> ThreatRule:
    defaults = dict(
        id="TEST-001",
        name="test rule",
        severity=Severity.HIGH,
        description="test",
        match={},
        action=Action.DENY,
    )
    defaults.update(kwargs)
    return ThreatRule(**defaults)


# --- H6: policy glob matching ---


class TestPolicyGlobMatching:
    def test_dot_is_escaped(self):
        # Unescaped dot previously matched any char; "*" does not cross "/"
        assert not _arguments_match({"path": "/home/user/venv"}, {"path": "/home/user/*.env"})
        assert _arguments_match({"path": "/home/user/.env"}, {"path": "/home/user/*.env"})
        assert not _arguments_match({"path": "venv"}, {"path": "*.env"})
        assert _arguments_match({"path": ".env"}, {"path": "*.env"})

    def test_pattern_is_anchored(self):
        assert not _arguments_match({"path": "key.pemx"}, {"path": "*.pem"})
        assert _arguments_match({"path": "key.pem"}, {"path": "*.pem"})
        assert not _arguments_match({"path": "xsecret"}, {"path": "secret*"})

    def test_question_mark_matches_single_char(self):
        assert _arguments_match({"path": "id_a"}, {"path": "id_?"})
        assert not _arguments_match({"path": "id_ab"}, {"path": "id_?"})

    def test_regex_metachars_are_escaped(self):
        assert not _arguments_match({"path": "filextxt"}, {"path": "file.txt"})
        assert _arguments_match({"path": "a+b"}, {"path": "a+b"})

    def test_globstar_crosses_directories(self):
        assert _arguments_match({"path": "/etc/a/b/c"}, {"path": "/etc/**"})
        assert not _arguments_match({"path": "/etc/a/b"}, {"path": "/etc/*"})

    def test_policy_engine_end_to_end(self):
        config = GatewayConfig(
            default_action=Action.ALLOW,
            rules=[
                RuleConfig(
                    name="no-env",
                    tool="*",
                    match={"arguments": {"path": "**/*.env"}},
                    action=Action.DENY,
                )
            ],
        )
        engine = PolicyEngine()
        denied = engine.evaluate(make_request(args={"path": "/home/user/.env"}), config)
        assert denied is not None and denied.action == Action.DENY
        allowed = engine.evaluate(make_request(args={"path": "/home/user/venv"}), config)
        assert allowed is None


# --- H6/L7: threat feed rule matching ---


class TestThreatRuleGlobs:
    def test_env_glob_does_not_match_venv(self):
        rule = make_rule(match={"arguments": {"path": "*.env"}})
        assert not rule.matches("read_file", {"path": "/home/user/venv"})
        assert rule.matches("read_file", {"path": "/home/user/.env"})

    def test_pem_glob_does_not_match_pemx(self):
        rule = make_rule(match={"arguments": {"path": "*.pem"}})
        assert not rule.matches("read_file", {"path": "key.pemx"})
        assert rule.matches("read_file", {"path": "key.pem"})

    def test_alternation_still_works(self):
        rule = make_rule(match={"arguments": {"path": "*.env|*.netrc"}})
        assert rule.matches("read_file", {"path": "/root/.netrc"})
        assert not rule.matches("read_file", {"path": "/root/netrc"})

    def test_tool_pattern_glob_and_alternation(self):
        rule = make_rule(match={"tool": "http_*|fetch"})
        assert rule.matches("http_post", {})
        assert rule.matches("fetch", {})
        assert not rule.matches("read_file", {})

    def test_non_string_pattern_disables_rule(self, caplog):
        with caplog.at_level(logging.WARNING):
            rule = make_rule(match={"arguments": {"path": 123}})
        assert rule._compile_failed
        assert not rule.matches("read_file", {"path": "123"})
        assert "TEST-001" in caplog.text

    def test_invalid_description_regex_disables_rule(self, caplog):
        with caplog.at_level(logging.WARNING):
            rule = make_rule(match={"description": "([invalid"})
        assert rule._compile_failed
        assert not rule.matches("read_file", {"path": "anything"})

    def test_non_string_value_is_matched_as_string(self):
        rule = make_rule(match={"arguments": {"port": "443*"}})
        assert rule.matches("connect", {"port": 4433})
        # Previously the check was skipped and the rule matched anyway
        rule_env = make_rule(match={"arguments": {"path": "*.env"}})
        assert not rule_env.matches("read_file", {"path": 123})


# --- M3: rate limit rule matching ---


class TestRateLimitRuleMatching:
    def make_config(self, rule: RuleConfig) -> GatewayConfig:
        return GatewayConfig(default_action=Action.ALLOW, rules=[rule])

    def test_glob_pattern_fires(self):
        rule = RuleConfig(
            name="limit-http",
            tool="fetch|http_*",
            rate_limit={"maxCalls": 2, "windowSeconds": 60},
        )
        config = self.make_config(rule)
        rl = RateLimiter()
        assert rl.evaluate(make_request(tool="http_get"), config) is None
        assert rl.evaluate(make_request(tool="http_get"), config) is None
        result = rl.evaluate(make_request(tool="http_get"), config)
        assert result is not None and result.action == Action.DENY
        assert "limit-http" in result.reason

    def test_tool_matches_simple_globs(self):
        assert _tool_matches_simple("http_get", "fetch|http_*")
        assert _tool_matches_simple("anything", "*")
        assert not _tool_matches_simple("read_file", "fetch|http_*")

    def test_rule_match_arguments_respected(self):
        rule = RuleConfig(
            name="limit-etc",
            tool="read_file",
            match={"arguments": {"path": "/etc/*"}},
            rate_limit={"maxCalls": 1, "windowSeconds": 60},
        )
        config = self.make_config(rule)
        rl = RateLimiter()
        # Calls with non-matching arguments are never limited
        for _ in range(5):
            assert rl.evaluate(make_request(args={"path": "/tmp/x"}), config) is None  # noqa: S108 - inert path fixture; no temporary I/O
        # Matching arguments hit the limit
        assert rl.evaluate(make_request(args={"path": "/etc/passwd"}), config) is None
        result = rl.evaluate(make_request(args={"path": "/etc/shadow"}), config)
        assert result is not None and result.action == Action.DENY


# --- M6: bounded maps ---


class TestBoundedMaps:
    def test_rate_limiter_per_agent_bounded(self, monkeypatch):
        monkeypatch.setattr(rate_limiter, "_MAX_WINDOWS", 10)
        config = GatewayConfig(default_action=Action.ALLOW)
        rl = RateLimiter()
        for i in range(100):
            rl.evaluate(make_request(agent=f"agent-{i}"), config)
        assert len(rl._per_agent) <= 10

    def test_chain_detector_history_bounded(self, monkeypatch):
        monkeypatch.setattr(chain_detector, "_MAX_AGENTS", 10)
        config = GatewayConfig(default_action=Action.ALLOW)
        cd = ChainDetector()
        for i in range(100):
            cd.evaluate(make_request(tool="read_file", agent=f"agent-{i}"), config)
        assert len(cd._history) <= 10

    def test_chain_detector_still_detects_after_eviction(self, monkeypatch):
        monkeypatch.setattr(chain_detector, "_MAX_AGENTS", 5)
        config = GatewayConfig(default_action=Action.ALLOW)
        cd = ChainDetector()
        cd.evaluate(make_request(tool="read_file", agent="attacker"), config)
        result = cd.evaluate(make_request(tool="bash", agent="attacker"), config)
        assert result is not None and result.action == Action.DENY
