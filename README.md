# 🛡️ mcp-firewall

**The open-source security gateway for AI agents.**

mcp-firewall sits between your MCP client and server, intercepting every tool call with enterprise-grade policy enforcement, real-time threat detection, and compliance-ready audit logging.

```
AI Agent ←→ mcp-firewall ←→ MCP Server
               ↕
         Policy Engine
         Audit Trail
         Threat Feed
```

## Why

AI agents can now execute tools — read files, run commands, query databases, make HTTP requests. Without guardrails, a single prompt injection can exfiltrate your credentials, execute arbitrary code, and chain tools for privilege escalation.

mcp-firewall is the WAF for AI agents.

## Quick Start

```bash
pip install mcp-firewall

# Wrap any MCP server with zero config
mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp

# Generate a starter policy
mcp-firewall init
```

## Features

### 🔒 Defense-in-Depth Pipeline
Every tool call passes through 7 inbound security stages (plus optional human approval) and 2 outbound scanners:

**Inbound** (request screening):
1. Kill Switch — Emergency deny-all
2. Rate Limiter — Per-agent, per-tool, global
3. Injection Detector — Pattern-based, sensitivity configurable (low/medium/high)
4. Egress Control — Block SSRF, private IPs, cloud metadata
5. Threat Feed — Known attack patterns (built-in community rules)
6. Policy Engine — YAML policies + per-agent RBAC
7. Chain Detector — Dangerous tool sequences

When a rule requires approval, an interactive prompt asks the user; non-interactive sessions fail closed (deny).

**Outbound** (response scanning):
1. Secret Scanner — API keys, tokens, private keys
2. PII Detector — Email, phone, SSN, IBAN, credit cards

### 📋 Policy-as-Code

Simple YAML for common rules:
```yaml
agents:
  claude-desktop:
    allow: [read_file, search]
    deny: [exec, shell, rm]
    rate_limit: 100/min

rules:
  - name: block-credentials
    match: { arguments: { path: "**/.ssh/**" } }
    action: deny
```

See [Policy Reference](docs/policies.md) for the full rule schema.

### 📊 Real-Time Dashboard

```bash
mcp-firewall wrap --dashboard -- python my_server.py
# → Dashboard at http://localhost:9090
```

Live event feed and statistics.

### 🔏 Signed Audit Trail

Enable `audit.sign: true` to sign every event with Ed25519 in addition to the hash chain. Export to SIEM (CEF/LEEF), Syslog, CSV, or JSON.

```bash
mcp-firewall audit    # Verify chain integrity
mcp-firewall audit export --format cef --output siem.log
```

### 📄 Compliance Reports

Auto-generated evidence for regulatory audits:

```bash
mcp-firewall report dora     # EU Digital Operational Resilience Act
mcp-firewall report finma    # Swiss Financial Market Authority
mcp-firewall report soc2     # SOC 2 Type II evidence
```

### 🎯 Threat Feed

Community-maintained detection rules (like Sigma for SIEM):

```bash
mcp-firewall feed list       # Show active rules
```

Rules detect known-bad patterns: webhook exfiltration, credential harvesting, cloud metadata SSRF, and more.

### 🔍 Built-in Scanner

Pre-deployment security scanning (powered by [mcpwn](https://github.com/ressl/mcpwn)):

```bash
mcp-firewall scan -- python my_server.py
```

## Integration

Works with every MCP client — zero code changes:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/home"]
    }
  }
}
```

Compatible with: Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, and any MCP client.

## Architecture

```
┌─────────────┐     ┌──────────────────────────────┐     ┌─────────────┐
│  MCP Client │◄───►│          mcp-firewall            │◄───►│  MCP Server │
└─────────────┘     │                               │     └─────────────┘
                    │  Inbound ─► Policy ─► Outbound│
                    │      │         │         │     │
                    │      ▼         ▼         ▼     │
                    │  [Audit] [Alerts] [Metrics]    │
                    │      │                         │
                    │      ▼                         │
                    │  [Dashboard]  [Reports]        │
                    └──────────────────────────────--┘
```

## Comparison

| Feature | mcp-firewall | Agent-Wall | LlamaFirewall | MintMCP |
|---|---|---|---|---|
| MCP-native proxy | ✅ | ✅ | ❌ | ✅ (SaaS) |
| Open source | ✅ | ✅ | ✅ | ❌ |
| Agent RBAC | ✅ | ❌ | ❌ | ❌ |
| Signed audit trail | ✅ | ❌ | ❌ | ❌ |
| Compliance reports | ✅ | ❌ | ❌ | SOC2 only |
| Threat feed | ✅ | ❌ | ❌ | ❌ |
| Alerting | ✅ | ❌ | ❌ | ❌ |
| Dashboard | ✅ | Basic | ❌ | ✅ |
| Cost tracking | ✅ | ❌ | ❌ | ❌ |
| Built-in scanner | ✅ | ❌ | ❌ | ❌ |

## Use Cases

- **Developers**: Protect your machine when trying new MCP servers
- **Security Teams**: Enforce tool usage policies across the organization
- **Compliance Officers**: Generate audit evidence for DORA, FINMA, SOC 2
- **CISOs**: Visibility and control over AI agent behavior
- **Red Teamers**: Test AI agent security posture

## SDK Mode (any AI agent framework)

mcp-firewall works as a Python library, not just an MCP proxy. Use it with OpenClaw, LangChain, CrewAI, or any custom agent:

```python
from mcp_firewall.sdk import Gateway

with Gateway(config_path="mcp-firewall.yaml") as gw:
    decision = gw.check("read_file", {"path": "/tmp/example.txt"}, agent="my-agent")
    if decision.blocked:
        print(f"Blocked: {decision.reason}")
    else:
        # Illustrative output: the SDK itself never executes the tool.
        output = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        result = gw.scan_response(output, context=decision.context)
        print(result.content)  # "AWS_KEY=[REDACTED by mcp-firewall]"
```

See [examples/openclaw_integration.py](examples/openclaw_integration.py) for a full example.

SDK approval requests now fail closed by default, and configured audit logging is
respected. See the [SDK migration guide](docs/sdk-migration.md) for changed defaults,
async methods, structured responses, and resource cleanup.

## Desktop approvals

Use `mcp-firewall wrap --dashboard-approvals -- <server>` for authenticated,
single-call approval in the local dashboard. Set `MCP_FIREWALL_DASHBOARD_TOKEN`
and connect the controller first. Missing approval, timeout or controller loss
denies the call; global restrictions still apply. See [setup and limits](docs/desktop-approvals.md).

A [native AgentReins adapter](integrations/agentreins/README.md) adds the same
approval controls and correlated protocol evidence to a pinned AgentReins development build.

## Integration events

Export versioned lifecycle events to a local desktop companion or another HTTP
receiver. Events correlate admission and response decisions using session and call
IDs, with bounded background delivery and sanitized metadata. Audit entries and
the dashboard use the same event model. Export never grants permission or proves
that a tool executed.

See [the integration contract](docs/integration-events.md),
[JSON schema](docs/integration-events.schema.json), and
[example receiver](examples/event_receiver.py).

## See Also

**[mcpwn](https://github.com/ressl/mcpwn)** — Security scanner for MCP servers. While mcp-firewall protects at *runtime*, mcpwn finds vulnerabilities *before deployment*.

| Tool | When | What |
|---|---|---|
| **mcpwn** | Pre-deployment | Find vulnerabilities in MCP servers |
| **mcp-firewall** | Runtime | Block attacks, enforce policies, audit logging |

Scan first, then protect:

```bash
# Step 1: Scan for vulnerabilities
mcp-firewall scan -- python my_server.py

# Step 2: Protect at runtime
mcp-firewall wrap -- python my_server.py
```

## Scoped workspace recovery

Opt in to before/after file snapshots with `wrap --dashboard-approvals
--snapshot-workspace /absolute/project`. The native adapter can display diffs and
restore a selected file while rejecting stale edits. Snapshots are bounded and
last for the proxy process lifetime; pause external writers before restore.
See [workspace rollback](docs/workspace-rollback.md) for setup and limits.

## Documentation

- [Getting Started](docs/getting-started.md)
- [Policy Reference](docs/policies.md)
- [Compliance Guide](docs/compliance.md)
- [Threat Feed](docs/threat-feed.md)
- [Architecture](ARCHITECTURE.md)
- [Workspace snapshots and rollback](docs/workspace-rollback.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Security issues: see [SECURITY.md](SECURITY.md).

## License

AGPL-3.0 — see [LICENSE](LICENSE).

Commercial licensing available for organizations that cannot use AGPL. Contact rr@canus.ch.

## About

Built by [Robert Ressl](https://linkedin.com/in/robertressl) — Associate Director Offensive Security at Kyndryl. CISSP, OSEP, OSCP, CRTO. After 100+ penetration tests and red team engagements across banking, insurance, and critical infrastructure, I saw the gap: AI agents are the new attack surface, and MCP is the protocol everyone uses but nobody secures.

mcp-firewall is the firewall that MCP needs.
