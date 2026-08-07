"""Regression tests for review finding M1 — SSRF bypasses in egress control."""

from __future__ import annotations

import pytest

from mcp_firewall.models import Action, GatewayConfig, Severity, ToolCallRequest
from mcp_firewall.pipeline.inbound.egress import EgressControl


def make_request(args: dict) -> ToolCallRequest:
    return ToolCallRequest(tool_name="fetch", arguments=args, agent_id="unknown")


def evaluate(args: dict, config: GatewayConfig | None = None):
    return EgressControl().evaluate(make_request(args), config or GatewayConfig())


# --- M1(1): embedded URLs with dangerous schemes are never extracted ---

class TestDangerousSchemeExtraction:
    @pytest.mark.parametrize("scheme", ["gopher", "dict", "ftp", "ldap"])
    def test_embedded_dangerous_scheme(self, scheme):
        result = evaluate({"text": f"see {scheme}://internal.host/data for details"})
        assert result is not None
        assert result.action == Action.DENY
        assert result.severity == Severity.HIGH

    @pytest.mark.parametrize("scheme", ["gopher", "dict", "ldap"])
    def test_direct_value_dangerous_scheme(self, scheme):
        result = evaluate({"url": f"{scheme}://internal.host/data"})
        assert result is not None
        assert result.action == Action.DENY


# --- M1(2): case-sensitive startswith check ---

class TestCaseInsensitiveScheme:
    def test_uppercase_scheme_direct_value(self):
        result = evaluate({"url": "GOPHER://internal.host/data"})
        assert result is not None
        assert result.action == Action.DENY

    def test_mixed_case_scheme_embedded(self):
        result = evaluate({"text": "open Dict://internal.host:11211/stats"})
        assert result is not None
        assert result.action == Action.DENY

    def test_uppercase_file_scheme(self):
        result = evaluate({"url": "FILE:///etc/passwd"})
        assert result is not None
        assert result.action == Action.DENY


# --- M1(3): bare IPs / hostnames as argument values ---

class TestBareHostValues:
    def test_bare_cloud_metadata_ip(self):
        result = evaluate({"host": "169.254.169.254"})
        assert result is not None
        assert result.action == Action.DENY
        assert result.severity == Severity.CRITICAL

    def test_bare_cloud_metadata_hostname(self):
        result = evaluate({"host": "metadata.google.internal"})
        assert result is not None
        assert result.action == Action.DENY

    def test_bare_private_ip(self):
        result = evaluate({"host": "192.168.0.1"})
        assert result is not None
        assert result.action == Action.DENY

    def test_bare_loopback_ip(self):
        result = evaluate({"host": "127.0.0.1"})
        assert result is not None
        assert result.action == Action.DENY

    def test_bare_dword_loopback_ip(self):
        # 2130706433 == 127.0.0.1 as a single decimal number (inet_aton dword)
        result = evaluate({"host": "2130706433"})
        assert result is not None
        assert result.action == Action.DENY

    def test_port_number_is_not_a_host(self):
        # Values that fit in a port must not be treated as dword IPs
        result = evaluate({"port": "8080"})
        assert result is None

    def test_bare_public_ip_allowed(self):
        assert evaluate({"host": "8.8.8.8"}) is None

    def test_bare_public_hostname_allowed(self):
        assert evaluate({"host": "example.com"}) is None

    def test_plain_number_not_treated_as_host(self):
        # ports and other plain numeric values must not false-positive
        assert evaluate({"port": "8080"}) is None

    def test_plain_word_not_treated_as_host(self):
        assert evaluate({"mode": "readonly"}) is None


# --- M1(4): non-canonical IPv4 forms bypass ipaddress ---

class TestIPv4Normalization:
    def test_short_form_in_url(self):
        result = evaluate({"url": "http://127.1/"})
        assert result is not None
        assert result.action == Action.DENY

    def test_octal_form_in_url(self):
        result = evaluate({"url": "http://0177.0.0.1/"})
        assert result is not None
        assert result.action == Action.DENY

    def test_short_form_bare_value(self):
        result = evaluate({"host": "127.1"})
        assert result is not None
        assert result.action == Action.DENY

    def test_metadata_short_form(self):
        # 169.254.43518 == 169.254.169.254
        result = evaluate({"url": "http://169.254.43518/latest/meta-data"})
        assert result is not None
        assert result.action == Action.DENY
        assert result.severity == Severity.CRITICAL

    def test_hex_form_in_url(self):
        result = evaluate({"url": "http://0x7f000001/"})
        assert result is not None
        assert result.action == Action.DENY

    def test_decimal_form_in_url(self):
        # 2130706433 == 127.0.0.1
        result = evaluate({"url": "http://2130706433/"})
        assert result is not None
        assert result.action == Action.DENY

    def test_hex_part_form_in_url(self):
        result = evaluate({"url": "http://0x7f.0.0.1/"})
        assert result is not None
        assert result.action == Action.DENY

    def test_metadata_only_config_still_blocks_short_form(self):
        config = GatewayConfig()
        config.egress.block_private_ips = False
        result = evaluate({"url": "http://169.254.43518/latest/meta-data"}, config)
        assert result is not None
        assert result.action == Action.DENY


# --- M1(5): recursion depth and lists-in-lists ---

class TestRecursion:
    def test_deeply_nested_dict(self):
        args = {"url": "http://169.254.169.254/latest/meta-data"}
        for _ in range(8):
            args = {"nested": args}
        result = evaluate(args)
        assert result is not None
        assert result.action == Action.DENY

    def test_list_in_list(self):
        result = evaluate({"urls": [["http://169.254.169.254/latest/meta-data"]]})
        assert result is not None
        assert result.action == Action.DENY

    def test_deeply_nested_lists(self):
        result = evaluate({"a": [[[{"b": ["http://10.0.0.1/internal"]}]]]})
        assert result is not None
        assert result.action == Action.DENY

    def test_dangerous_scheme_in_list_in_list(self):
        result = evaluate({"a": [["gopher://internal.host/"]]})
        assert result is not None
        assert result.action == Action.DENY

    def test_bare_ip_in_list(self):
        result = evaluate({"hosts": ["example.com", "169.254.169.254"]})
        assert result is not None
        assert result.action == Action.DENY
