"""Tests for Phase 4: Signed audit, compliance reports, threat feed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_firewall.audit.signer import AuditSigner
from mcp_firewall.audit.logger import AuditLogger
from mcp_firewall.compliance.report import AuditData, generate_dora_report, generate_finma_report, generate_soc2_report
from mcp_firewall.models import Action, GatewayConfig, ToolCallRequest
from mcp_firewall.threatfeed.loader import ThreatFeed, ThreatRule
from mcp_firewall.models import Severity


def make_request(tool: str = "read_file", args: dict | None = None) -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, arguments=args or {})


# --- Ed25519 Signer ---

class TestAuditSigner:
    def test_generate_and_sign(self, tmp_path):
        signer = AuditSigner(key_path=tmp_path / "test.key")
        data = '{"test": "data"}'
        sig = signer.sign(data)
        assert isinstance(sig, str)
        assert len(sig) > 0

    def test_verify_valid(self, tmp_path):
        signer = AuditSigner(key_path=tmp_path / "test.key")
        data = "hello world"
        sig = signer.sign(data)
        assert signer.verify(data, sig) is True

    def test_verify_tampered(self, tmp_path):
        signer = AuditSigner(key_path=tmp_path / "test.key")
        data = "hello world"
        sig = signer.sign(data)
        assert signer.verify("tampered data", sig) is False

    def test_load_existing_key(self, tmp_path):
        # Generate
        signer1 = AuditSigner(key_path=tmp_path / "test.key")
        sig1 = signer1.sign("test")
        # Load
        signer2 = AuditSigner(key_path=tmp_path / "test.key")
        assert signer2.verify("test", sig1) is True

    def test_public_key_pem(self, tmp_path):
        signer = AuditSigner(key_path=tmp_path / "test.key")
        pem = signer.public_key_pem
        assert "PUBLIC KEY" in pem

    def test_key_file_permissions(self, tmp_path):
        signer = AuditSigner(key_path=tmp_path / "test.key")
        key_path = tmp_path / "test.key"
        # Check key file exists and is restricted
        assert key_path.exists()
        assert oct(key_path.stat().st_mode)[-3:] == "600"


# --- Signed Audit Logger ---

class TestSignedAuditLogger:
    def test_signed_entries(self, tmp_path):
        config = GatewayConfig()
        config.audit.path = str(tmp_path / "signed.audit.jsonl")
        config.audit.sign = True

        # Need key in cwd for signer
        import os
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            logger = AuditLogger(config)
            logger.log(make_request(), None)
            logger.log(make_request(), None)

            # Read back and verify signatures exist
            lines = Path(config.audit.path).read_text().splitlines()
            assert len(lines) == 2
            for line in lines:
                entry = json.loads(line)
                assert "signature" in entry
                assert len(entry["signature"]) > 0
        finally:
            os.chdir(old_cwd)


# --- Compliance Reports ---

class TestComplianceReports:
    def _create_audit_log(self, tmp_path) -> Path:
        """Create a sample audit log for testing."""
        log_path = tmp_path / "test.audit.jsonl"
        events = [
            {"timestamp": 1708000000, "agent_id": "claude", "tool_name": "read_file",
             "decision": "allow", "severity": "info", "stage": "policy"},
            {"timestamp": 1708000001, "agent_id": "claude", "tool_name": "exec",
             "decision": "deny", "severity": "high", "stage": "injection",
             "reason": "Prompt injection detected"},
            {"timestamp": 1708000002, "agent_id": "cursor", "tool_name": "search",
             "decision": "allow", "severity": "info", "stage": "policy"},
            {"timestamp": 1708000003, "agent_id": "claude", "tool_name": "http_post",
             "decision": "deny", "severity": "critical", "stage": "chain_detector",
             "reason": "Dangerous tool chain"},
            {"timestamp": 1708000004, "agent_id": "cursor", "tool_name": "read_file",
             "decision": "redact", "severity": "medium", "stage": "secret_scanner",
             "reason": "AWS key redacted"},
        ]
        with open(log_path, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        return log_path

    def test_audit_data_parsing(self, tmp_path):
        log_path = self._create_audit_log(tmp_path)
        data = AuditData(log_path)
        assert data.total == 5
        assert data.denied == 2
        assert data.allowed == 2
        assert data.redacted == 1
        assert len(data.critical_events) == 2  # high + critical

    def test_dora_report(self, tmp_path):
        log_path = self._create_audit_log(tmp_path)
        report = generate_dora_report(log_path)
        assert "DORA" in report
        assert "Art. 9" in report
        assert "Art. 11" in report
        assert "5" in report  # total events
        assert "mcp-firewall" in report

    def test_finma_report(self, tmp_path):
        log_path = self._create_audit_log(tmp_path)
        report = generate_finma_report(log_path)
        assert "FINMA" in report
        assert "claude" in report
        assert "IBAN" in report or "AHV" in report or "Data Protection" in report

    def test_soc2_report(self, tmp_path):
        log_path = self._create_audit_log(tmp_path)
        report = generate_soc2_report(log_path)
        assert "SOC 2" in report
        assert "CC6" in report
        assert "CC7" in report

    def test_empty_audit(self, tmp_path):
        log_path = tmp_path / "empty.jsonl"
        log_path.touch()
        report = generate_dora_report(log_path)
        assert "DORA" in report
        assert "0" in report


# --- Threat Feed ---

class TestThreatFeed:
    def test_load_builtin_rules(self):
        tf = ThreatFeed()
        rules_dir = Path(__file__).parent.parent / "mcp_firewall" / "threatfeed" / "rules"
        count = tf.load_directory(rules_dir)
        assert count >= 5
        assert len(tf.rules) >= 5

    def test_webhook_exfil_rule(self):
        tf = ThreatFeed()
        rules_dir = Path(__file__).parent.parent / "mcp_firewall" / "threatfeed" / "rules"
        tf.load_directory(rules_dir)

        match = tf.check("http_post", {"url": "https://webhook.site/abc123"})
        assert match is not None
        assert match.id == "TF-001"

    def test_credential_harvesting_rule(self):
        tf = ThreatFeed()
        rules_dir = Path(__file__).parent.parent / "mcp_firewall" / "threatfeed" / "rules"
        tf.load_directory(rules_dir)

        match = tf.check("read_file", {"path": "/home/user/.ssh/id_rsa"})
        assert match is not None
        assert match.id == "TF-003"

    def test_no_match(self):
        tf = ThreatFeed()
        rules_dir = Path(__file__).parent.parent / "mcp_firewall" / "threatfeed" / "rules"
        tf.load_directory(rules_dir)

        match = tf.check("read_file", {"path": "/home/user/readme.txt"})
        assert match is None

    def test_list_rules(self):
        tf = ThreatFeed()
        rules_dir = Path(__file__).parent.parent / "mcp_firewall" / "threatfeed" / "rules"
        tf.load_directory(rules_dir)

        listing = tf.list_rules()
        assert len(listing) >= 5
        assert all("id" in r and "name" in r for r in listing)

    def test_custom_rule(self, tmp_path):
        rule_file = tmp_path / "custom.yaml"
        rule_file.write_text("""
id: CUSTOM-001
name: Block Internal API
severity: high
description: Block access to internal API
match:
  arguments:
    url: "*internal-api.corp.local*"
action: deny
tags: [custom, internal]
""")
        tf = ThreatFeed()
        tf.load_file(rule_file)
        match = tf.check("fetch", {"url": "https://internal-api.corp.local/secrets"})
        assert match is not None
        assert match.id == "CUSTOM-001"


class TestThreatRule:
    def test_severity_comparison(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.LOW < Severity.HIGH
        assert Severity.INFO <= Severity.LOW
