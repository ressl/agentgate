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
Every tool call passes through 8 inbound + 4 outbound security checks:

**Inbound** (request screening):
1. Kill Switch — Emergency deny-all
2. Agent Identity — RBAC per AI agent
3. Rate Limiter — Per-agent, per-tool, global
4. Injection Detector — 50+ patterns
5. Egress Control — Block SSRF, private IPs, cloud metadata
6. Policy Engine — OPA/Rego + YAML policies
7. Chain Detector — Dangerous tool sequences
8. Human Approval — Optional interactive prompt

**Outbound** (response scanning):
1. Secret Scanner — API keys, tokens, private keys
2. PII Detector — Email, phone, SSN, IBAN, credit cards
3. Exfil Detector — Embedded URLs, base64, DNS tunneling
4. Content Policy — Custom domain-specific rules

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

Full OPA/Rego for complex policies:
```rego
package mcp-firewall.policy

allow {
    input.agent == "cursor"
    input.tool.name == "read_file"
    not sensitive_path(input.tool.arguments.path)
}
```

### 📊 Real-Time Dashboard

```bash
mcp-firewall wrap --dashboard -- python my_server.py
# → Dashboard at http://localhost:9090
```

Live event feed, analytics, alert history, and policy playground.

### 🔏 Signed Audit Trail

Every event is cryptographically signed (Ed25519) with a hash chain for tamper detection. Export to SIEM (CEF/LEEF), Syslog, CSV, or JSON.

```bash
mcp-firewall audit verify    # Verify chain integrity
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
mcp-firewall feed update     # Pull latest rules
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
| OPA/Rego policies | ✅ | ❌ | ❌ | ❌ |
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

gw = Gateway()  # or Gateway(config_path="mcp-firewall.yaml")

# Check before executing a tool
decision = gw.check("exec", {"command": "rm -rf /"}, agent="my-agent")
if decision.blocked:
    print(f"Blocked: {decision.reason}")

# Scan tool output for leaked secrets
result = gw.scan_response("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
print(result.content)  # "AWS_KEY=[REDACTED by mcp-firewall]"
```

See [examples/openclaw_integration.py](examples/openclaw_integration.py) for a full example.

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

## Documentation

- [Getting Started](docs/getting-started.md)
- [Policy Reference](docs/policies.md)
- [Compliance Guide](docs/compliance.md)
- [Threat Feed](docs/threat-feed.md)
- [Architecture](ARCHITECTURE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Security issues: see [SECURITY.md](SECURITY.md).

## License

AGPL-3.0 — see [LICENSE](LICENSE).

Commercial licensing available for organizations that cannot use AGPL. Contact rr@canus.ch.

## About

Built by [Robert Ressl](https://linkedin.com/in/robertressl) — Associate Director Offensive Security at Kyndryl. CISSP, OSEP, OSCP, CRTO. After 100+ penetration tests and red team engagements across banking, insurance, and critical infrastructure, I saw the gap: AI agents are the new attack surface, and MCP is the protocol everyone uses but nobody secures.

mcp-firewall is the firewall that MCP needs.
