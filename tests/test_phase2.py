"""Tests for Phase 2: Rate limiter, chain detection, human approval."""

from __future__ import annotations

import time

from mcp_firewall.models import (
    Action,
    AgentConfig,
    GatewayConfig,
    RuleConfig,
    ToolCallRequest,
)
from mcp_firewall.pipeline.inbound.rate_limiter import RateLimiter, _parse_rate_limit
from mcp_firewall.pipeline.inbound.chain_detector import ChainDetector
from mcp_firewall.pipeline.inbound.human_approval import HumanApproval


def make_request(tool: str = "read_file", args: dict | None = None, agent: str = "test-agent") -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, arguments=args or {}, agent_id=agent)


def make_config(**kwargs) -> GatewayConfig:
    return GatewayConfig(**kwargs)


# --- Rate Limiter ---

class TestRateLimiter:
    def test_under_limit(self):
        config = make_config()
        config.rate_limit.max_calls = 10
        config.rate_limit.window_seconds = 60
        rl = RateLimiter()
        for _ in range(9):
            result = rl.evaluate(make_request(), config)
            assert result is None

    def test_over_global_limit(self):
        config = make_config()
        config.rate_limit.max_calls = 5
        config.rate_limit.window_seconds = 60
        rl = RateLimiter()
        for _ in range(5):
            rl.evaluate(make_request(), config)
        result = rl.evaluate(make_request(), config)
        assert result is not None
        assert result.action == Action.DENY
        assert "Global rate limit" in result.reason

    def test_per_agent_limit(self):
        config = make_config(
            agents={"claude": AgentConfig(rate_limit="3/min")},
        )
        config.rate_limit.max_calls = 1000  # High global limit
        rl = RateLimiter()
        for _ in range(3):
            rl.evaluate(make_request(agent="claude"), config)
        result = rl.evaluate(make_request(agent="claude"), config)
        assert result is not None
        assert result.action == Action.DENY
        assert "Agent rate limit" in result.reason

    def test_different_agents_independent(self):
        config = make_config(
            agents={
                "claude": AgentConfig(rate_limit="2/min"),
                "cursor": AgentConfig(rate_limit="2/min"),
            },
        )
        config.rate_limit.max_calls = 1000
        rl = RateLimiter()
        for _ in range(2):
            rl.evaluate(make_request(agent="claude"), config)
        # Claude is at limit, but cursor is not
        result = rl.evaluate(make_request(agent="cursor"), config)
        assert result is None

    def test_disabled(self):
        config = make_config()
        config.rate_limit.enabled = False
        rl = RateLimiter()
        for _ in range(1000):
            result = rl.evaluate(make_request(), config)
        assert result is None


class TestParseRateLimit:
    def test_per_minute(self):
        assert _parse_rate_limit("100/min") == (100, 60)

    def test_per_second(self):
        assert _parse_rate_limit("10/sec") == (10, 1)

    def test_per_hour(self):
        assert _parse_rate_limit("500/hour") == (500, 3600)

    def test_short_form(self):
        assert _parse_rate_limit("50/m") == (50, 60)
        assert _parse_rate_limit("10/s") == (10, 1)
        assert _parse_rate_limit("200/h") == (200, 3600)


# --- Chain Detector ---

class TestChainDetector:
    def test_single_tool_ok(self):
        cd = ChainDetector()
        config = make_config()
        result = cd.evaluate(make_request(tool="read_file"), config)
        assert result is None

    def test_read_then_exec(self):
        cd = ChainDetector()
        config = make_config()
        # First: read a file
        cd.evaluate(make_request(tool="read_file"), config)
        # Then: execute a command (dangerous chain!)
        result = cd.evaluate(make_request(tool="exec"), config)
        assert result is not None
        assert result.action == Action.DENY
        assert "chain" in result.reason.lower()

    def test_read_then_http_post(self):
        cd = ChainDetector()
        config = make_config()
        cd.evaluate(make_request(tool="read_file"), config)
        result = cd.evaluate(make_request(tool="http_post"), config)
        assert result is not None
        assert "exfiltration" in result.reason.lower()

    def test_db_query_then_send(self):
        cd = ChainDetector()
        config = make_config()
        cd.evaluate(make_request(tool="query"), config)
        result = cd.evaluate(make_request(tool="fetch_url"), config)
        assert result is not None

    def test_safe_sequence(self):
        cd = ChainDetector()
        config = make_config()
        cd.evaluate(make_request(tool="read_file"), config)
        result = cd.evaluate(make_request(tool="read_file"), config)
        assert result is None  # read+read is fine

    def test_different_agents_independent(self):
        cd = ChainDetector()
        config = make_config()
        cd.evaluate(make_request(tool="read_file", agent="alice"), config)
        # Bob's exec shouldn't chain with Alice's read
        result = cd.evaluate(make_request(tool="exec", agent="bob"), config)
        assert result is None

    def test_reset(self):
        cd = ChainDetector()
        config = make_config()
        cd.evaluate(make_request(tool="read_file"), config)
        cd.reset()
        result = cd.evaluate(make_request(tool="exec"), config)
        assert result is None  # History cleared


# --- Human Approval ---

class TestHumanApproval:
    def test_auto_approve(self):
        ha = HumanApproval(auto_approve=True)
        config = make_config()
        result = ha.evaluate(make_request(), config)
        assert result is not None
        assert result.action == Action.ALLOW


# --- Integration: Pipeline with all Phase 2 stages ---

class TestPipelinePhase2:
    def test_rate_limit_in_pipeline(self):
        config = make_config(default_action=Action.ALLOW)
        config.rate_limit.max_calls = 3
        config.audit.enabled = False
        from mcp_firewall.pipeline.runner import PipelineRunner
        runner = PipelineRunner(config)
        for _ in range(3):
            runner.evaluate_inbound(make_request())
        result = runner.evaluate_inbound(make_request())
        assert result is not None
        assert result.action == Action.DENY

    def test_chain_detection_in_pipeline(self):
        config = make_config(default_action=Action.ALLOW)
        config.rate_limit.max_calls = 1000
        config.audit.enabled = False
        from mcp_firewall.pipeline.runner import PipelineRunner
        runner = PipelineRunner(config)
        runner.evaluate_inbound(make_request(tool="read_file"))
        result = runner.evaluate_inbound(make_request(tool="http_post"))
        assert result is not None
        assert result.action == Action.DENY
