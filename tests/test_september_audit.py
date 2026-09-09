"""Regression coverage for signature verification, reload and multiple writers."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_firewall.audit.logger import AuditLogger
from mcp_firewall.audit.signer import AuditSigner
from mcp_firewall.cli import main
from mcp_firewall.models import Action, GatewayConfig, ToolCallRequest
from mcp_firewall.pipeline.runner import PipelineRunner
from mcp_firewall.sdk import Gateway


def config(tmp_path, sign=False):
    c = GatewayConfig(default_action=Action.ALLOW)
    c.audit.path = str(tmp_path / "audit.jsonl")
    c.audit.sign = sign
    return c


@pytest.fixture
def signed_log(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "keys"))
    logger = AuditLogger(config(tmp_path, sign=True))
    logger.log(ToolCallRequest(tool_name="first"), None)
    logger.log(ToolCallRequest(tool_name="second"), None)
    return logger


@pytest.mark.parametrize("tamper", ["last", "rechain", "remove_signature"])
def test_signed_tampering_rejected(signed_log, tamper):
    entries = [json.loads(line) for line in signed_log.path.read_text().splitlines()]
    if tamper == "remove_signature":
        entries[-1].pop("signature")
    else:
        entries[-1 if tamper == "last" else 0]["tool_name"] = "tampered"
    lines = []
    for entry in entries:
        if tamper == "rechain" and lines:
            entry["previous_hash"] = hashlib.sha256(lines[-1].encode()).hexdigest()
        lines.append(json.dumps(entry, separators=(",", ":")))
    signed_log.path.write_text("\n".join(lines) + "\n")
    valid, _, error = signed_log.verify_chain()
    assert not valid
    assert "signature" in error.lower()


def test_verification_uses_only_public_key(signed_log, tmp_path, monkeypatch):
    key = signed_log._signer._key_path
    public_key = key.with_suffix(".pub")
    key.unlink()
    c = config(tmp_path, sign=True)
    with monkeypatch.context() as m:
        m.setattr(
            AuditSigner, "__init__", lambda *args, **kwargs: pytest.fail("private-key access")
        )
        verifier = AuditLogger(c, verification_only=True)
        assert verifier.verify_chain(public_key_path=public_key)[0]
    assert not key.exists()


def test_wrong_or_missing_public_key_rejected(signed_log, tmp_path):
    wrong = AuditSigner(tmp_path / "wrong.key")._pub_path
    assert not signed_log.verify_chain(public_key_path=wrong)[0]
    assert not signed_log.verify_chain(public_key_path=tmp_path / "missing.pub")[0]


def test_signature_checked_even_if_config_does_not_require_it(signed_log, tmp_path):
    entries = signed_log.path.read_text().splitlines()
    entry = json.loads(entries[-1])
    entry["reason"] = "tampered"
    entries[-1] = json.dumps(entry)
    signed_log.path.write_text("\n".join(entries) + "\n")
    assert not AuditLogger(config(tmp_path), verification_only=True).verify_chain()[0]


def test_cli_public_key_verification(signed_log, tmp_path):
    cpath = tmp_path / "config.yaml"
    cpath.write_text(f"audit:\n  path: {signed_log.path}\n  sign: true\n")
    key = signed_log._signer._key_path
    pub = key.with_suffix(".pub")
    key.unlink()
    result = CliRunner().invoke(main, ["audit", "--config", str(cpath), "--public-key", str(pub)])
    assert result.exit_code == 0, result.output
    assert "2 entries" in result.output
    assert not key.exists()


def test_separate_writers_preserve_chain(tmp_path):
    a = AuditLogger(config(tmp_path))
    b = AuditLogger(config(tmp_path))
    for i in range(20):
        (a if i % 2 else b).log(ToolCallRequest(tool_name=f"call-{i}"), None)
    assert a.verify_chain()[:2] == (True, 20)


def test_multiple_writers_coordinate_rotation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "keys"))
    c = config(tmp_path, sign=True)
    a = AuditLogger(c)
    b = AuditLogger(c)
    a._max_bytes = b._max_bytes = 2000
    for i in range(40):
        (a if i % 2 else b).log(ToolCallRequest(tool_name=str(i)), None)
    assert a.verify_chain()[0]
    c.audit.path += ".1"
    assert AuditLogger(c, verification_only=True).verify_chain()[0]
    previous = Path(c.audit.path).read_text().splitlines()[-1]
    current = json.loads(a.path.read_text().splitlines()[0])
    assert hashlib.sha256(previous.encode()).hexdigest() in current["reason"]


def test_cli_can_require_signatures_on_an_unsigned_log(tmp_path):
    c = config(tmp_path)
    logger = AuditLogger(c)
    logger.log(ToolCallRequest(tool_name="status"), None)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"audit:\n  path: {logger.path}\n")
    result = CliRunner().invoke(main, ["audit", "--config", str(cfg), "--require-signatures"])
    assert result.exit_code == 1
    assert "Missing signature" in result.output


@pytest.mark.parametrize("raw", [b"\xff\n", b"[]\n", b'{"previous_hash":null}\n'])
def test_invalid_audit_entries_report_failure(tmp_path, raw):
    c = config(tmp_path)
    Path(c.audit.path).write_bytes(raw)
    valid, _, error = AuditLogger(c, verification_only=True).verify_chain()
    assert not valid
    assert error


def test_process_writers_share_signing_key_and_chain(tmp_path):
    code = """
import sys
from mcp_firewall.models import GatewayConfig, ToolCallRequest
from mcp_firewall.audit.logger import AuditLogger
c = GatewayConfig(audit={'path': sys.argv[1], 'sign': True})
logger = AuditLogger(c)
for i in range(30):
    logger.log(ToolCallRequest(tool_name='status'), None)
"""
    env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path / "keys")}
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path / "audit.jsonl")],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(4)
    ]
    try:
        for p in processes:
            out, err = p.communicate(timeout=20)
            assert p.returncode == 0, err.decode()
        verifier = AuditLogger(config(tmp_path, sign=True), verification_only=True)
        public_key = tmp_path / "keys/mcp-firewall/mcp-firewall.pub"
        assert verifier.verify_chain(public_key_path=public_key)[:2] == (True, 120)
    finally:
        for p in processes:
            if p.poll() is None:
                p.kill()
            p.wait()


def test_reload_applies_audit_enable_disable_path_and_limit(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "keys"))
    c = config(tmp_path)
    c.audit.enabled = False
    runner = PipelineRunner(c)
    enabled = config(tmp_path, sign=True)
    enabled.audit.max_size_mb = 2
    runner.reload_config(enabled)
    runner.evaluate_inbound(ToolCallRequest(tool_name="status"))
    assert runner.audit.enabled
    assert runner.audit._max_bytes == 2 * 1024 * 1024
    assert runner.audit.verify_chain()[:2] == (True, 1)
    moved = enabled.model_copy(deep=True)
    moved.audit.path = str(tmp_path / "moved.jsonl")
    runner.reload_config(moved)
    runner.evaluate_inbound(ToolCallRequest(tool_name="other"))
    assert Path(moved.audit.path).exists()
    runner.reload_config(c)
    runner.evaluate_inbound(ToolCallRequest(tool_name="unlogged"))
    assert len(Path(enabled.audit.path).read_text().splitlines()) == 1


def test_reload_signing_mode_rotates_to_verifiable_generation(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "keys"))
    c = config(tmp_path)
    runner = PipelineRunner(c)
    runner.evaluate_inbound(ToolCallRequest(tool_name="unsigned"))
    signed = c.model_copy(deep=True)
    signed.audit.sign = True
    runner.reload_config(signed)
    runner.evaluate_inbound(ToolCallRequest(tool_name="signed"))
    assert Path(c.audit.path + ".1").exists()
    assert runner.audit.verify_chain()[0]
    assert all(
        "signature" in json.loads(line) for line in Path(c.audit.path).read_text().splitlines()
    )
    runner.reload_config(c)
    runner.evaluate_inbound(ToolCallRequest(tool_name="unsigned-again"))
    assert runner.audit.verify_chain()[0]
    assert all(
        "signature" not in json.loads(line) for line in Path(c.audit.path).read_text().splitlines()
    )


def test_failed_reload_keeps_previous_configuration(tmp_path):
    gw = Gateway(config=config(tmp_path))
    original = gw.config
    bad = tmp_path / "bad.yaml"
    bad.write_text(f"defaultAction: deny\nthreatFeed:\n  feedDir: {tmp_path / 'missing'}\n")
    with pytest.raises(ValueError):
        gw.reload(bad)
    assert gw.config is original
    assert gw._pipeline.config is original
