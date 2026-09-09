"""Composed security regressions for September findings 1–4, 6, 10 and 11."""

import asyncio
import json
import socket
import threading
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from mcp_firewall.config import load_config
from mcp_firewall.models import (
    Action,
    AgentConfig,
    GatewayConfig,
    RuleConfig,
    ToolCallRequest,
    ToolCallResponse,
)
from mcp_firewall.pipeline.inbound.egress import EgressControl
from mcp_firewall.pipeline.inbound.policy import PolicyEngine
from mcp_firewall.pipeline.inbound.rate_limiter import RateLimiter
from mcp_firewall.pipeline.runner import PipelineRunner
from mcp_firewall.sdk import Gateway
from mcp_firewall.threatfeed.loader import ThreatFeed

SECRET = "AKIA" + "Z" * 16


def config():
    return GatewayConfig(default_action=Action.ALLOW, audit={"enabled": False})


@pytest.mark.parametrize("field", ["content", "structured_content", "extra_fields"])
def test_scanners_cover_nested_response_values(field):
    c = config()
    c.pii.enabled = True
    response = ToolCallResponse(request_id="r")
    value = {"nested": [{"key": SECRET, "email": "alice@example.com"}]}
    if field == "content":
        response.content = [
            {"type": "resource", "resource": {"uri": "file:///test", "text": json.dumps(value)}}
        ]
    else:
        setattr(response, field, value)
    scanned, decisions = PipelineRunner(c).scan_outbound(
        ToolCallRequest(tool_name="status"), response
    )
    serialized = scanned.model_dump_json()
    assert SECRET not in serialized
    assert "alice@example.com" not in serialized
    assert {d.stage.value for d in decisions} == {"secret_scanner", "pii_detector"}


@pytest.mark.parametrize("fmt", [PrivateFormat.PKCS8, PrivateFormat.TraditionalOpenSSL])
def test_pem_material_is_removed(fmt):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(Encoding.PEM, fmt, NoEncryption()).decode()
    result = Gateway(config=config()).scan_response("before\n" + pem + "after")
    assert result.modified
    assert pem.splitlines()[1] not in result.content
    assert "PRIVATE KEY" not in result.content
    assert result.content.startswith("before\n")
    assert result.content.endswith("after")


def test_unterminated_private_key_consumes_remaining_material():
    result = Gateway(config=config()).scan_response(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material"
    )
    assert result.modified
    assert "private-material" not in result.content


def test_enterprise_allowlist_still_checks_credential_rules():
    c = load_config("examples/policies/enterprise.yaml")
    c.audit.enabled = False
    result = Gateway(config=c).check(
        "read_file", {"path": "/home/alice/.kube/config"}, agent="claude-desktop"
    )
    assert result.blocked
    assert "block-kube" in result.reason


@pytest.mark.parametrize("global_action", [Action.ALLOW, Action.DENY, Action.PROMPT])
def test_agent_approval_does_not_override_global_restrictions(global_action):
    c = config()
    c.agents["bot"] = AgentConfig(require_approval=["write_file"])
    c.rules = [RuleConfig(name="global", tool="write_file", action=global_action)]
    result = PolicyEngine().evaluate(ToolCallRequest(tool_name="write_file", agent_id="bot"), c)
    assert result.action == (Action.DENY if global_action == Action.DENY else Action.PROMPT)


@pytest.mark.parametrize("async_mode", [False, True])
async def test_explicit_allow_does_not_skip_chain(async_mode):
    c = config()
    c.rules = [RuleConfig(name="allow", tool="read_file|http_post", action=Action.ALLOW)]
    runner = PipelineRunner(c)

    async def run(tool):
        request = ToolCallRequest(tool_name=tool, agent_id="bot")
        return (
            await runner.aevaluate_inbound(request)
            if async_mode
            else runner.evaluate_inbound(request)
        )

    assert await run("read_file") is None
    result = await run("http_post")
    assert result.action == Action.DENY
    assert result.stage.value == "chain_detector"


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost:8080/x",
        "http://LOCALHOST./",
        "http://sub.localhost/",
        "::1",
        "[::1]",
        "http://127.0.0.1./",
        "fd00::1",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_private_destinations_blocked(value):
    result = EgressControl().evaluate(
        ToolCallRequest(tool_name="fetch", arguments={"host": value}), config()
    )
    assert result is not None and result.action == Action.DENY


@pytest.mark.parametrize("addresses", [["10.0.0.1"], ["8.8.8.8", "::1"], ["169.254.169.254"]])
def test_dns_private_answers_blocked(addresses):
    with patch(
        "mcp_firewall.pipeline.inbound.egress.getaddrinfo",
        return_value=[(2, 1, 6, "", (a, 0)) for a in addresses],
    ):
        result = EgressControl().evaluate(
            ToolCallRequest(tool_name="fetch", arguments={"url": "https://service.example/x"}),
            config(),
        )
    assert result is not None and result.action == Action.DENY


def test_filename_does_not_trigger_dns_lookup():
    with patch(
        "mcp_firewall.pipeline.inbound.egress.getaddrinfo",
        side_effect=AssertionError("not a network destination"),
    ):
        assert (
            EgressControl().evaluate(
                ToolCallRequest(tool_name="read_file", arguments={"path": "report.txt"}), config()
            )
            is None
        )


@pytest.mark.parametrize(
    "bad_rule",
    ["severity: higgh", "match: {description: '[bad'}", "match: {arguments: {path: 123}}"],
)
def test_invalid_feed_is_rejected_atomically(tmp_path, bad_rule):
    (tmp_path / "a.yaml").write_text("id: GOOD\nname: good\nmatch: {tool: harmless}\n")
    (tmp_path / "b.yaml").write_text("id: BAD\nname: bad\n" + bad_rule + "\n")
    feed = ThreatFeed()
    with pytest.raises(ValueError, match="b.yaml"):
        feed.load_directory(tmp_path)
    assert feed.rules == []


def test_missing_enabled_custom_feed_rejected(tmp_path):
    c = config()
    c.threat_feed.feed_dir = str(tmp_path / "missing")
    with pytest.raises(ValueError, match="missing"):
        PipelineRunner(c)


def test_disabled_custom_feed_is_not_loaded(tmp_path):
    c = config()
    c.threat_feed.enabled = False
    c.threat_feed.feed_dir = str(tmp_path / "missing")
    PipelineRunner(c)


def test_no_unconfigured_agent_history():
    limiter = RateLimiter()
    c = config()
    for n in range(5000):
        with patch(
            "mcp_firewall.pipeline.inbound.rate_limiter.time.time", return_value=100000 + n * 61
        ):
            assert limiter.evaluate(ToolCallRequest(tool_name="status", agent_id="bot"), c) is None
    assert not limiter._per_agent


def test_unknown_agent_limit_is_enforced():
    c = config()
    c.agents["unknown"] = AgentConfig(rate_limit="1/min")
    limiter = RateLimiter()
    request = ToolCallRequest(tool_name="status")
    assert limiter.evaluate(request, c) is None
    assert limiter.evaluate(request, c).action == Action.DENY


@pytest.mark.parametrize(
    "label", ["ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK", "OPENSSH PRIVATE KEY"]
)
def test_complete_and_truncated_key_blocks(label):
    for ending in [f"\n-----END {label}-----", ""]:
        result = Gateway(config=config()).scan_response(
            f"-----BEGIN {label}-----\nkey-material{ending}"
        )
        assert result.modified
        assert "key-material" not in result.content


def test_shared_result_references_are_not_mistaken_for_cycles():
    value = {"token": SECRET}
    response = ToolCallResponse(request_id="1", structured_content={"a": value, "b": value})
    scanned, _ = PipelineRunner(config()).scan_outbound(
        ToolCallRequest(tool_name="status"), response
    )
    assert SECRET not in scanned.model_dump_json()


def test_dns_failure_denies_and_disabled_protection_does_not_resolve():
    request = ToolCallRequest(tool_name="fetch", arguments={"url": "https://unresolved.example"})
    with patch("mcp_firewall.pipeline.inbound.egress.getaddrinfo", side_effect=socket.gaierror()):
        assert EgressControl().evaluate(request, config()).action == Action.DENY
    c = config()
    c.egress.block_private_ips = c.egress.block_cloud_metadata = False
    with patch(
        "mcp_firewall.pipeline.inbound.egress.getaddrinfo", side_effect=AssertionError("disabled")
    ):
        assert EgressControl().evaluate(request, c) is None


def test_metadata_only_block_checks_ipv4_mapped_ipv6():
    c = config()
    c.egress.block_private_ips = False
    request = ToolCallRequest(
        tool_name="fetch", arguments={"url": "http://[::ffff:169.254.169.254]/"}
    )
    assert EgressControl().evaluate(request, c).severity.value == "critical"


def test_egress_depth_limit_denies_instead_of_skipping():
    arguments = {"url": "http://127.0.0.1"}
    for _ in range(20):
        arguments = {"nested": arguments}
    assert (
        EgressControl()
        .evaluate(ToolCallRequest(tool_name="fetch", arguments=arguments), config())
        .action
        == Action.DENY
    )


async def test_async_dns_does_not_block_protocol_loop(monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def lookup(*args, **kwargs):
        entered.set()
        release.wait(timeout=3)
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr("mcp_firewall.pipeline.inbound.egress.getaddrinfo", lookup)
    runner = PipelineRunner(config())
    task = asyncio.create_task(
        runner.aevaluate_inbound(
            ToolCallRequest(tool_name="fetch", arguments={"url": "https://example.com"})
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        # This task can run while the resolver is still waiting.
        assert not task.done()
    finally:
        release.set()
    assert await task is None


def test_validate_checks_enabled_feed_files(tmp_path):
    from click.testing import CliRunner

    from mcp_firewall.cli import main

    cpath = tmp_path / "config.yaml"
    cpath.write_text(f"threatFeed:\n  feedDir: {tmp_path / 'missing'}\n")
    result = CliRunner().invoke(main, ["validate", "--config", str(cpath)])
    assert result.exit_code == 1
    assert "missing" in result.output
