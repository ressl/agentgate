"""Tests for code-review fixes: audit logger, signer, compliance reports (Group F).

Covers: M7 (hash chain race), M8 (max_size_mb rotation), M16 (None stage rows),
L5 (key location/permissions), L6 (resume-chain warning), L8 (report numbers),
L9 (streaming AuditData, full signature scan), L14 (verify_chain missing file).
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from mcp_firewall.audit.logger import AuditLogger
from mcp_firewall.audit.signer import AuditSigner
from mcp_firewall.compliance.report import (
    AuditData,
    generate_dora_report,
    generate_soc2_report,
)
from mcp_firewall.models import GatewayConfig, ToolCallRequest


def make_request(tool: str = "read_file", args: dict | None = None) -> ToolCallRequest:
    return ToolCallRequest(tool_name=tool, arguments=args or {})


def make_logger(tmp_path, **audit_overrides) -> AuditLogger:
    config = GatewayConfig()
    config.audit.path = str(tmp_path / "test.audit.jsonl")
    for key, value in audit_overrides.items():
        setattr(config.audit, key, value)
    return AuditLogger(config)


# --- M7: hash chain is race-free under concurrent log() calls ---

class TestHashChainRace:
    def test_concurrent_loggers_keep_chain_intact(self, tmp_path):
        logger = make_logger(tmp_path)
        threads = [
            threading.Thread(target=lambda: [logger.log(make_request(), None) for _ in range(50)])
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert logger.entry_count == 400
        is_valid, count, error = logger.verify_chain()
        assert is_valid, error
        assert count == 400


# --- M8: audit.max_size_mb rotation ---

class TestLogRotation:
    def test_rotation_on_size_limit(self, tmp_path):
        logger = make_logger(tmp_path)
        logger._max_bytes = 600  # shrink limit for the test
        for _ in range(10):
            logger.log(make_request(), None)

        rotated = Path(str(logger.path) + ".1")
        assert rotated.exists(), "old generation should be kept as <path>.1"

        # New file starts a fresh, verifiable chain headed by a rotation marker
        is_valid, count, error = logger.verify_chain()
        assert is_valid, error
        first = json.loads(Path(logger.path).read_text().splitlines()[0])
        assert first["previous_hash"] == "genesis"
        assert first["tool_name"] == "audit.rotate"
        assert "previous chain head:" in first["reason"]

    def test_no_rotation_below_limit(self, tmp_path):
        logger = make_logger(tmp_path)
        logger.log(make_request(), None)
        assert not Path(str(logger.path) + ".1").exists()
        first = json.loads(Path(logger.path).read_text().splitlines()[0])
        assert first["tool_name"] == "read_file"

    def test_rotation_marker_references_old_head(self, tmp_path):
        logger = make_logger(tmp_path)
        logger._max_bytes = 600
        for _ in range(10):
            logger.log(make_request(), None)

        old_lines = Path(str(logger.path) + ".1").read_text().splitlines()
        import hashlib
        old_head = hashlib.sha256(old_lines[-1].encode()).hexdigest()
        first = json.loads(Path(logger.path).read_text().splitlines()[0])
        assert old_head in first["reason"]


# --- L6: corrupt log resume warns instead of silently swallowing ---

class TestResumeChain:
    def test_corrupt_last_line_warns(self, tmp_path, caplog):
        log_path = tmp_path / "test.audit.jsonl"
        log_path.write_text('{"previous_hash": "genesis"}\nnot-json{{{\n')
        config = GatewayConfig()
        config.audit.path = str(log_path)
        with caplog.at_level(logging.WARNING, logger="mcp_firewall.audit.logger"):
            AuditLogger(config)
        assert any("resume audit hash chain" in r.message for r in caplog.records)

    def test_valid_log_resumes_silently(self, tmp_path, caplog):
        logger = make_logger(tmp_path)
        logger.log(make_request(), None)
        config = GatewayConfig()
        config.audit.path = str(tmp_path / "test.audit.jsonl")
        with caplog.at_level(logging.WARNING, logger="mcp_firewall.audit.logger"):
            resumed = AuditLogger(config)
        assert resumed.entry_count == 1
        assert not caplog.records


# --- L14: verify_chain distinguishes missing file from empty file ---

class TestVerifyChainMissingFile:
    def test_missing_file_is_distinguishable(self, tmp_path):
        logger = make_logger(tmp_path)
        is_valid, count, error = logger.verify_chain()
        assert not is_valid
        assert count == 0
        assert "not found" in error.lower()

    def test_empty_existing_file_is_valid(self, tmp_path):
        logger = make_logger(tmp_path)
        Path(logger.path).touch()
        is_valid, count, error = logger.verify_chain()
        assert is_valid
        assert count == 0
        assert error == ""


# --- L5: signing key location and permissions ---

class TestSigningKeyDefaults:
    def test_default_key_path_under_config_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        signer = AuditSigner()
        assert signer._key_path.is_absolute()
        assert signer._key_path == tmp_path / "mcp-firewall" / "mcp-firewall.key"
        assert signer._key_path.exists()
        assert oct(signer._key_path.stat().st_mode)[-3:] == "600"

    def test_key_created_with_restrictive_permissions(self, tmp_path):
        import os
        old_umask = os.umask(0o022)  # permissive umask must not widen key perms
        try:
            signer = AuditSigner(key_path=tmp_path / "sub" / "dir" / "k.key")
        finally:
            os.umask(old_umask)
        assert oct((tmp_path / "sub" / "dir" / "k.key").stat().st_mode)[-3:] == "600"
        assert signer.sign("data")


# --- M16: null stage must not render as "None" rows ---

class TestStageNone:
    def _log_with_null_stage(self, tmp_path) -> Path:
        log_path = tmp_path / "audit.jsonl"
        events = [
            {"timestamp": 1708000000, "agent_id": "a", "tool_name": "t",
             "decision": "allow", "severity": "info", "stage": None},
            {"timestamp": 1708000001, "agent_id": "a", "tool_name": "t",
             "decision": "deny", "severity": "high", "stage": "injection"},
        ]
        with open(log_path, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        return log_path

    def test_null_stage_counted_as_none(self, tmp_path):
        data = AuditData(self._log_with_null_stage(tmp_path))
        assert data.by_stage["none"] == 1
        assert None not in data.by_stage

    def test_reports_have_no_none_rows(self, tmp_path):
        log_path = self._log_with_null_stage(tmp_path)
        for report in (generate_dora_report(log_path), generate_soc2_report(log_path)):
            assert "| None |" not in report
            assert "| none |" in report


# --- L9: streaming AuditData, full signature scan, real report numbers (L8) ---

class TestAuditDataStreaming:
    def test_no_full_event_list_retained(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        with open(log_path, "w") as f:
            for i in range(20):
                f.write(json.dumps({"timestamp": 1708000000 + i, "agent_id": "a",
                                    "tool_name": "t", "decision": "allow",
                                    "severity": "info", "stage": "policy"}) + "\n")
        data = AuditData(log_path)
        assert data.total == 20
        assert not hasattr(data, "events")

    def test_signature_detected_beyond_first_ten_events(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        with open(log_path, "w") as f:
            for i in range(15):
                event = {"timestamp": 1708000000 + i, "agent_id": "a", "tool_name": "t",
                         "decision": "allow", "severity": "info", "stage": "policy"}
                if i == 14:  # signature only in the last event
                    event["signature"] = "abc"
                f.write(json.dumps(event) + "\n")
        data = AuditData(log_path)
        assert data.has_signatures
        assert "signatures enabled" in generate_dora_report(log_path)

    def test_agent_denied_counter(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        with open(log_path, "w") as f:
            for decision, agent in [("deny", "x"), ("deny", "x"), ("allow", "x"), ("deny", "y")]:
                f.write(json.dumps({"timestamp": 1708000000, "agent_id": agent,
                                    "tool_name": "t", "decision": decision,
                                    "severity": "info", "stage": "policy"}) + "\n")
        data = AuditData(log_path)
        assert data.by_agent_denied["x"] == 2
        assert data.by_agent_denied["y"] == 1

    def test_report_pattern_counts_are_real(self, tmp_path):
        log_path = tmp_path / "audit.jsonl"
        log_path.touch()
        report = generate_soc2_report(log_path)
        assert "50+ patterns" not in report
        assert "17 patterns" in report  # Secret Scanner
        assert "7 patterns" in report  # PII Detector
        assert "8 security stages" not in report
