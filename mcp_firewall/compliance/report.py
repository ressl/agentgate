"""Compliance report generator — DORA, FINMA, SOC2."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Action, Severity


class AuditData:
    """Parsed audit log data for report generation."""

    def __init__(self, audit_path: str | Path) -> None:
        self.path = Path(audit_path)
        self.events: list[dict[str, Any]] = []
        self.total = 0
        self.denied = 0
        self.allowed = 0
        self.redacted = 0
        self.by_severity: Counter = Counter()
        self.by_stage: Counter = Counter()
        self.by_tool: Counter = Counter()
        self.by_agent: Counter = Counter()
        self.critical_events: list[dict[str, Any]] = []
        self.first_timestamp: float | None = None
        self.last_timestamp: float | None = None

        if self.path.exists():
            self._parse()

    def _parse(self) -> None:
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                self.events.append(event)
                self.total += 1

                action = event.get("decision", "allow")
                if action == "deny":
                    self.denied += 1
                elif action == "redact":
                    self.redacted += 1
                else:
                    self.allowed += 1

                severity = event.get("severity", "info")
                self.by_severity[severity] += 1
                self.by_stage[event.get("stage", "none")] += 1
                self.by_tool[event.get("tool_name", "unknown")] += 1
                self.by_agent[event.get("agent_id", "unknown")] += 1

                if severity in ("critical", "high"):
                    self.critical_events.append(event)

                ts = event.get("timestamp")
                if ts:
                    if self.first_timestamp is None or ts < self.first_timestamp:
                        self.first_timestamp = ts
                    if self.last_timestamp is None or ts > self.last_timestamp:
                        self.last_timestamp = ts

    @property
    def period(self) -> str:
        if self.first_timestamp and self.last_timestamp:
            start = datetime.fromtimestamp(self.first_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
            end = datetime.fromtimestamp(self.last_timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
            return f"{start} — {end} UTC"
        return "No data"


def generate_dora_report(audit_path: str | Path) -> str:
    """Generate DORA (Digital Operational Resilience Act) compliance report.

    Covers: Art. 9 (ICT Risk Management), Art. 11 (Logging & Monitoring)
    """
    data = AuditData(audit_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# DORA Compliance Report — AI Agent Security Controls
## mcp-firewall Audit Evidence

**Generated:** {now}
**Audit Period:** {data.period}
**Total Events:** {data.total:,}

---

## 1. ICT Risk Management (Art. 9)

### 1.1 AI Agent Tool Call Monitoring
mcp-firewall provides real-time monitoring and policy enforcement for all AI agent
tool calls via the MCP (Model Context Protocol) protocol.

| Metric | Value |
|---|---|
| Total tool calls monitored | {data.total:,} |
| Calls allowed | {data.allowed:,} |
| Calls denied (policy violation) | {data.denied:,} |
| Responses redacted (data protection) | {data.redacted:,} |
| Denial rate | {data.denied / max(data.total, 1) * 100:.1f}% |

### 1.2 Threat Detection
Automated detection across {len(data.by_stage)} security categories:

| Category | Events |
|---|---|
"""
    for stage, count in data.by_stage.most_common():
        report += f"| {stage} | {count:,} |\n"

    report += f"""
### 1.3 Critical Security Events
{len(data.critical_events)} critical/high severity events detected during audit period.

## 2. Logging and Monitoring (Art. 11)

### 2.1 Audit Trail Properties
- **Format:** Append-only JSON Lines with SHA-256 hash chain
- **Integrity:** Each entry references the hash of the previous entry
- **Signing:** {"Ed25519 digital signatures enabled" if any(e.get("signature") for e in data.events[:10]) else "Available (not enabled)"}
- **Tamper Detection:** Hash chain verification via `mcp-firewall audit verify`

### 2.2 Event Coverage
All MCP tool calls are logged with:
- Timestamp (ISO 8601)
- Agent identity
- Tool name and arguments hash (privacy-preserving)
- Security decision (allow/deny/redact)
- Pipeline stage that triggered the decision
- Severity classification
- Processing latency

### 2.3 Agent Activity Summary

| Agent | Calls | Denied |
|---|---|---|
"""
    agent_denied: Counter = Counter()
    for e in data.events:
        if e.get("decision") == "deny":
            agent_denied[e.get("agent_id", "unknown")] += 1

    for agent, count in data.by_agent.most_common(10):
        denied = agent_denied.get(agent, 0)
        report += f"| {agent} | {count:,} | {denied:,} |\n"

    report += f"""
## 3. Recommendations

1. {"⚠️ Enable Ed25519 audit signing for cryptographic integrity" if not any(e.get("signature") for e in data.events[:10]) else "✅ Ed25519 audit signing is enabled"}
2. {"⚠️ Review " + str(len(data.critical_events)) + " critical events" if data.critical_events else "✅ No critical events in audit period"}
3. Regularly verify audit chain integrity: `mcp-firewall audit verify`
4. Export audit logs to SIEM for centralized monitoring

---
*Report generated by mcp-firewall v0.1.0 — https://github.com/ressl/mcp-firewall*
"""
    return report


def generate_finma_report(audit_path: str | Path) -> str:
    """Generate FINMA (Swiss Financial Market Authority) compliance report.

    Covers: Operational risk documentation for AI agent systems.
    """
    data = AuditData(audit_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# FINMA Compliance Report — AI Agent Operational Risk
## mcp-firewall Audit Evidence

**Generated:** {now}
**Audit Period:** {data.period}
**Total Events:** {data.total:,}

---

## 1. Operational Risk Controls

### 1.1 AI Agent Access Control
Role-based access control (RBAC) enforced per AI agent identity:

| Agent | Total Calls | Denied | Denial Rate |
|---|---|---|---|
"""
    agent_denied: Counter = Counter()
    for e in data.events:
        if e.get("decision") == "deny":
            agent_denied[e.get("agent_id", "unknown")] += 1

    for agent, count in data.by_agent.most_common(10):
        denied = agent_denied.get(agent, 0)
        rate = denied / max(count, 1) * 100
        report += f"| {agent} | {count:,} | {denied:,} | {rate:.1f}% |\n"

    report += f"""
### 1.2 Data Protection
- **Secret Detection:** Automated scanning for API keys, tokens, credentials in tool responses
- **PII Detection:** Email, phone, IBAN, Swiss AHV number detection
- **Responses Redacted:** {data.redacted:,}
- **Policy:** Secrets redacted before reaching AI agent

### 1.3 Threat Mitigation
| Severity | Events |
|---|---|
"""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = data.by_severity.get(sev, 0)
        if count:
            report += f"| {sev.upper()} | {count:,} |\n"

    report += f"""
## 2. Audit Trail

- **Hash Chain:** SHA-256 linked entries, tamper-evident
- **Retention:** Configurable, stored at `{data.path}`
- **Verification:** `mcp-firewall audit verify`
- **Total Entries:** {data.total:,}

## 3. Summary

mcp-firewall provides continuous monitoring and policy enforcement for AI agent
tool interactions, supporting FINMA operational risk requirements for
automated systems in regulated financial environments.

---
*Report generated by mcp-firewall v0.1.0*
"""
    return report


def generate_soc2_report(audit_path: str | Path) -> str:
    """Generate SOC 2 Type II evidence report.

    Covers: CC6 (Logical Access), CC7 (System Operations), CC8 (Change Management)
    """
    data = AuditData(audit_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    report = f"""# SOC 2 Type II Evidence — AI Agent Security Controls
## mcp-firewall Audit Evidence

**Generated:** {now}
**Audit Period:** {data.period}
**Total Events:** {data.total:,}

---

## CC6: Logical and Physical Access Controls

### CC6.1 — Access to AI Agent Tools
mcp-firewall enforces policy-based access control on all AI agent tool invocations:

- **Policy Engine:** YAML-based rules with first-match-wins evaluation
- **Agent RBAC:** Per-agent allow/deny lists
- **Human Approval:** Interactive prompt for sensitive operations
- **Total Calls:** {data.total:,}
- **Denied:** {data.denied:,} ({data.denied / max(data.total, 1) * 100:.1f}%)

### CC6.3 — Access Removal
Kill switch mechanism provides emergency access revocation:
- File-based trigger
- SIGUSR1 signal
- Programmatic activation

## CC7: System Operations

### CC7.1 — Detection of Threats
Automated threat detection across 8 security stages:

| Detection Stage | Events |
|---|---|
"""
    for stage, count in data.by_stage.most_common():
        report += f"| {stage} | {count:,} |\n"

    report += f"""
### CC7.2 — Monitoring Activities
- **Real-time Dashboard:** WebSocket-based live event feed
- **Alerting:** Webhook, Slack, Syslog (CEF) channels
- **Audit Log:** Append-only with hash chain integrity
- **Severity Distribution:**
"""
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = data.by_severity.get(sev, 0)
        if count:
            report += f"  - {sev.upper()}: {count:,}\n"

    report += f"""
### CC7.3 — Evaluation of Threats
Security pipeline evaluates each tool call through:
1. Kill Switch (emergency deny-all)
2. Rate Limiter (abuse prevention)
3. Injection Detector (50+ patterns)
4. Egress Control (SSRF/private IP blocking)
5. Policy Engine (YAML rules + agent RBAC)
6. Chain Detector (dangerous tool sequences)
7. Human Approval (interactive prompt)

Plus outbound scanning:
8. Secret Scanner (18 patterns)
9. PII Detector (7 patterns)

## CC8: Change Management

### CC8.1 — Configuration Changes
- **Policy Hot-Reload:** Configuration changes apply without restart
- **YAML-as-Code:** Policies stored in version control
- **Audit Trail:** All policy decisions logged

---
*Report generated by mcp-firewall v0.1.0*
"""
    return report
