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
- **CC8** — Change Management (policy-as-code, runtime config reload via SDK)

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

`audit` verifies hash links and every present Ed25519 signature. With `audit.sign:
true`, it also rejects missing signatures. Public-key verification does not load
or generate a private key. The default public key is
`$XDG_CONFIG_HOME/mcp-firewall/mcp-firewall.pub`, or
`~/.config/mcp-firewall/mcp-firewall.pub` when XDG_CONFIG_HOME is unset.
For a copied log, supply the trusted public key explicitly:

```bash
mcp-firewall audit --config policy.yaml --public-key trusted.pub --require-signatures
```

Keep the trusted public key independent of an untrusted log. Replacing both the
log and its trust key defeats verification. Signatures authenticate retained
entries; detecting deletion of a valid suffix additionally requires a trusted
external checkpoint of the expected chain head. Unsigned hash chains provide
link consistency, not cryptographic proof of authorship.

Multiple writers using one path coordinate append and rotation through a separate
`<audit-path>.lock` file. They must use compatible signing settings and the same
signing key. Locks are intended for local filesystems with working native locking;
verify shared/network filesystem behavior separately. Do not remove an active
lock file. Key creation also uses a lock to avoid concurrent key replacement.

SDK reloads apply audit settings. A signing-mode change archives the current file
to `<audit-path>.1` and starts a new generation with a signed/unsigned rotation
marker recording the preceding head. Size rotation uses the same mechanism and
retains one old generation. Verify each generation with its corresponding signing
policy. Update all writers together when changing signing mode; a stale writer
refuses to append to a generation with a different mode. On process startup, use
a new log path when changing signing mode on an existing log.

Audit entries include individual outbound findings as well as inbound decisions;
entry counts should not be interpreted as unique tool-call counts. The dashboard
counts each outbound response once and shows blocked responses separately from
denied inbound calls, retaining the original request's tool and agent identity.

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
