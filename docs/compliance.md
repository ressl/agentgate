# Compliance Guide

mcp-firewall generates audit evidence for regulatory frameworks.

## DORA (EU Digital Operational Resilience Act)

```bash
mcp-firewall report dora --audit-log mcp-firewall.audit.jsonl --output dora-report.md
```

**Covers:**
- **Art. 9** — ICT Risk Management: AI agent monitoring evidence
- **Art. 11** — Logging and Monitoring: Audit trail documentation

## FINMA (Swiss Financial Market Authority)

```bash
mcp-firewall report finma --audit-log mcp-firewall.audit.jsonl --output finma-report.md
```

**Covers:**
- Operational risk controls for AI agent systems
- Data protection (secret/PII detection)
- Access control documentation

## SOC 2 Type II

```bash
mcp-firewall report soc2 --audit-log mcp-firewall.audit.jsonl --output soc2-evidence.md
```

**Covers:**
- **CC6** — Logical Access Controls (RBAC, kill switch)
- **CC7** — System Operations (threat detection, monitoring, alerting)
- **CC8** — Change Management (policy-as-code, hot reload)

## Audit Trail Integrity

Verify the hash chain:

```bash
mcp-firewall audit
```

Enable Ed25519 signing for cryptographic proof:

```yaml
audit:
  enabled: true
  sign: true
```

Each log entry contains:
- SHA-256 hash of previous entry (chain)
- Ed25519 signature (when enabled)
- Timestamp, agent, tool, decision, severity, latency

## SIEM Integration

Export audit logs to your SIEM:

### Syslog (CEF Format)
Configure in alerting channels for real-time CEF events.

### JSON Export
Audit log is newline-delimited JSON (JSONL), directly importable into:
- Splunk
- Elastic/OpenSearch
- Azure Sentinel
- QRadar
