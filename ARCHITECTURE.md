# mcp-firewall — Architecture & Project Plan

## Vision

**mcp-firewall** is the open-source security gateway for AI agents.
It sits between any MCP client and server, intercepting every tool call with enterprise-grade policy enforcement, real-time threat detection, and compliance-ready audit logging.

Think: **Cloudflare WAF meets AI agents.**

## Why mcp-firewall exists

AI agents are the new attack surface. MCP is the protocol. The problem:

1. **Developers** install MCP servers from GitHub without auditing them
2. **Enterprises** have no visibility into what AI agents do with their tools
3. **Regulators** (DORA, FINMA, NIS2) require audit trails for automated systems
4. **Security teams** have no WAF equivalent for agent-to-tool communication

### Competitive Landscape

| | Agent-Wall | LlamaFirewall | MintMCP | **mcp-firewall** |
|---|---|---|---|---|
| MCP-native proxy | ✅ | ❌ | ✅ (SaaS) | ✅ |
| Open source | ✅ | ✅ | ❌ | ✅ |
| Policy-as-Code | YAML | Python | ❌ | **OPA/Rego + YAML** |
| Compliance reports | ❌ | ❌ | SOC2 | **DORA, FINMA, SOC2** |
| Immutable audit trail | ❌ | ❌ | ✅ | **✅ (signed, tamper-proof)** |
| Threat intelligence | Basic regex | ML models | ❌ | **YARA-like rules + community feed** |
| Multi-agent support | ❌ | ✅ | ❌ | **✅ (agent identity, RBAC)** |
| Web dashboard | Basic | ❌ | ✅ | **✅ (real-time + historical)** |
| Cost/token tracking | ❌ | ❌ | ❌ | **✅** |
| Alerting (Slack/PD/webhook) | ❌ | ❌ | ❌ | **✅** |
| Language | TypeScript | Python | ❌ | **Python** |
| Maturity | 4 stars, 2 days | Meta-backed | Commercial | **NEW** |

### Our differentiation

1. **Compliance-first**: DORA/FINMA/SOC2 report generation out of the box
2. **OPA/Rego policies**: Industry-standard policy language, not custom YAML
3. **Signed audit trail**: Cryptographically signed, tamper-proof event log
4. **Threat feed**: Community-maintained rules (like Sigma for SIEM, YARA for malware)
5. **Agent identity**: RBAC per agent — "Claude can read files, GPT cannot exec shell"
6. **Alerting pipeline**: Real-time alerts to Slack, PagerDuty, webhooks, Syslog

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────────┐     ┌─────────────┐
│  MCP Client │     │                 mcp-firewall                    │     │  MCP Server  │
│  (Claude,   │◄───►│                                              │◄───►│  (any)       │
│   Cursor,   │     │  ┌──────────┐  ┌──────────┐  ┌───────────┐ │     │              │
│   VSCode)   │     │  │ Inbound  │  │  Policy   │  │ Outbound  │ │     └──────────────┘
│             │     │  │ Pipeline │─►│  Engine   │─►│ Pipeline  │ │
└─────────────┘     │  └──────────┘  │ (OPA/Rego)│  └───────────┘ │
                    │                └──────────┘                  │
                    │       │              │             │          │
                    │       ▼              ▼             ▼          │
                    │  ┌──────────────────────────────────────┐    │
                    │  │           Core Services               │    │
                    │  │  ┌────────┐ ┌────────┐ ┌──────────┐ │    │
                    │  │  │ Audit  │ │ Alert  │ │ Metrics  │ │    │
                    │  │  │ Logger │ │ Engine │ │ Tracker  │ │    │
                    │  │  └────────┘ └────────┘ └──────────┘ │    │
                    │  └──────────────────────────────────────┘    │
                    │       │                                      │
                    │       ▼                                      │
                    │  ┌──────────┐  ┌──────────┐                 │
                    │  │ Dashboard│  │ Reports  │                 │
                    │  │ (Web UI) │  │ (Export) │                 │
                    │  └──────────┘  └──────────┘                 │
                    └──────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Proxy (`mcp-firewall/proxy/`)
- Transparent stdio and SSE/Streamable HTTP proxy
- Zero-config wrapping of any MCP server
- Agent identity extraction (from client metadata or config)
- Connection pooling for SSE backends

### 2. Inbound Pipeline (`mcp-firewall/pipeline/inbound/`)
Sequential checks on every `tools/call` request:

| Stage | Check | Action |
|---|---|---|
| 1 | **Kill Switch** | Emergency deny-all (file trigger, signal, API) |
| 2 | **Agent Identity** | Identify calling agent, apply RBAC |
| 3 | **Rate Limiter** | Per-agent, per-tool, global limits |
| 4 | **Injection Detector** | 50+ patterns (prompt injection, Unicode, HTML) |
| 5 | **Egress Control** | Block private IPs, cloud metadata, SSRF |
| 6 | **Policy Engine** | Evaluate OPA/Rego policies |
| 7 | **Chain Detector** | Detect dangerous tool sequences |
| 8 | **Human Approval** | Optional: prompt user before execution |

### 3. Outbound Pipeline (`mcp-firewall/pipeline/outbound/`)
Scans every tool response:

| Stage | Check | Action |
|---|---|---|
| 1 | **Secret Scanner** | API keys, tokens, private keys, passwords |
| 2 | **PII Detector** | Email, phone, SSN, credit cards, IBAN |
| 3 | **Exfil Detector** | Embedded URLs, base64 payloads, DNS tunneling |
| 4 | **Content Policy** | Custom regex/rules for domain-specific data |

Actions: `pass` | `redact` | `block` | `alert`

### 4. Policy Engine (`mcp-firewall/policy/`)
- **OPA/Rego**: Industry-standard, used by Kubernetes, Terraform, etc.
- **YAML shortcuts**: Simple rules compile to Rego under the hood
- **Built-in policies**: Sensible defaults that block 90% of attacks
- **Hot reload**: Policy changes apply without restart

Example policy (YAML shortcut):
```yaml
version: 1
agents:
  claude-desktop:
    allow: [read_file, search, fetch]
    deny: [exec, shell, rm, delete]
    rate_limit: 100/min
  cursor:
    allow: [read_file, write_file, exec]
    deny: [http_post, fetch_url]
    require_approval: [exec]

rules:
  - name: block-ssh-keys
    match: { arguments: { path: "**/.ssh/**" } }
    action: deny

  - name: block-env-files
    match: { arguments: { path: "**/.env*" } }
    action: deny

  - name: approve-shell
    tool: "exec|shell|bash|run_command"
    action: prompt
```

Example policy (Rego for advanced users):
```rego
package mcp-firewall.policy

default allow = false

allow {
    input.agent == "claude-desktop"
    input.tool.name == "read_file"
    not sensitive_path(input.tool.arguments.path)
}

sensitive_path(p) { glob.match("**/.ssh/**", ["/"], p) }
sensitive_path(p) { glob.match("**/.env*", ["/"], p) }
sensitive_path(p) { glob.match("**/secrets/**", ["/"], p) }
```

### 5. Audit Logger (`mcp-firewall/audit/`)
- Every event logged as signed JSON line (Ed25519)
- Tamper detection: hash chain (each entry references previous hash)
- Fields: timestamp, agent_id, tool, arguments (redacted), result, decision, latency
- Export formats: JSON, CSV, SIEM (CEF/LEEF), Syslog
- Rotation and retention policies

### 6. Compliance Reports (`mcp-firewall/compliance/`)
Auto-generated reports:

- **DORA Art. 9**: ICT risk management evidence for AI tool usage
- **DORA Art. 11**: Logging and monitoring of automated systems
- **FINMA**: Operational risk documentation for AI agents
- **SOC 2 Type II**: Access control and monitoring evidence
- **ISO 27001 A.12**: Operations security logging

Report format: PDF + machine-readable JSON

### 7. Dashboard (`mcp-firewall/dashboard/`)
- Real-time WebSocket event feed
- Historical analytics (tool usage, block rates, latency)
- Agent activity overview
- Alert history
- Policy test playground (dry-run tool calls against policies)
- Built with: FastAPI + HTMX (no heavy JS framework)

### 8. Alert Engine (`mcp-firewall/alerts/`)
- Webhook (generic)
- Slack / Microsoft Teams
- PagerDuty
- Syslog / SIEM integration
- Email (SMTP)
- Alert rules: severity threshold, rate anomaly, specific patterns

### 9. Threat Feed (`mcp-firewall/threatfeed/`)
Community-maintained rule files (like Sigma/YARA):
```yaml
# threatfeed/rules/exfil-webhook.yaml
id: TF-001
name: Webhook Exfiltration
severity: high
description: Tool sends data to common webhook/paste services
match:
  arguments:
    url: "*webhook.site*|*requestbin*|*pipedream*|*ngrok*|*pastebin*"
action: deny
```

- GitHub-hosted rule repository
- Auto-update mechanism
- Community contributions via PR
- Versioned releases

## File Structure

```
mcp-firewall/
├── mcp-firewall/
│   ├── __init__.py
│   ├── __main__.py              # python -m mcp-firewall
│   ├── proxy/
│   │   ├── __init__.py
│   │   ├── stdio.py             # stdio transport proxy
│   │   ├── sse.py               # SSE transport proxy
│   │   └── streamable.py        # Streamable HTTP proxy
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── base.py              # Pipeline stage interface
│   │   ├── inbound/
│   │   │   ├── __init__.py
│   │   │   ├── kill_switch.py
│   │   │   ├── agent_identity.py
│   │   │   ├── rate_limiter.py
│   │   │   ├── injection.py
│   │   │   ├── egress.py
│   │   │   ├── chain_detector.py
│   │   │   └── human_approval.py
│   │   └── outbound/
│   │       ├── __init__.py
│   │       ├── secrets.py
│   │       ├── pii.py
│   │       ├── exfil.py
│   │       └── content.py
│   ├── policy/
│   │   ├── __init__.py
│   │   ├── engine.py            # OPA/Rego evaluation
│   │   ├── yaml_compiler.py     # YAML → Rego compiler
│   │   └── builtins.rego        # Default policies
│   ├── audit/
│   │   ├── __init__.py
│   │   ├── logger.py            # Signed JSON line logger
│   │   ├── chain.py             # Hash chain verification
│   │   └── export.py            # SIEM/CSV/Syslog export
│   ├── compliance/
│   │   ├── __init__.py
│   │   ├── dora.py
│   │   ├── finma.py
│   │   ├── soc2.py
│   │   └── report.py            # PDF generation
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── slack.py
│   │   ├── pagerduty.py
│   │   ├── webhook.py
│   │   └── syslog.py
│   ├── dashboard/
│   │   ├── __init__.py
│   │   ├── app.py               # FastAPI app
│   │   ├── ws.py                # WebSocket events
│   │   ├── templates/           # Jinja2 + HTMX
│   │   └── static/
│   ├── threatfeed/
│   │   ├── __init__.py
│   │   ├── loader.py
│   │   ├── updater.py
│   │   └── rules/               # Built-in rules
│   ├── cli.py                   # Click CLI
│   ├── config.py                # Configuration loading
│   └── models.py                # Pydantic models
├── tests/
│   ├── test_proxy.py
│   ├── test_pipeline.py
│   ├── test_policy.py
│   ├── test_audit.py
│   ├── test_compliance.py
│   └── conftest.py
├── examples/
│   ├── vulnerable_server.py     # Test target
│   ├── policies/
│   │   ├── minimal.yaml         # Starter policy
│   │   ├── enterprise.yaml      # Full lockdown
│   │   └── developer.yaml       # Balanced for devs
│   └── claude_desktop_config.json
├── threatfeed/
│   └── rules/                   # Community rules
├── docs/
│   ├── getting-started.md
│   ├── policies.md
│   ├── compliance.md
│   ├── threat-feed.md
│   └── architecture.md
├── pyproject.toml
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
└── .github/
    └── workflows/
        ├── ci.yml
        └── release.yml
```

## CLI Design

```bash
# Install
pip install mcp-firewall

# Quick start — wrap any MCP server
mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp
mcp-firewall wrap -- python my_mcp_server.py

# Initialize config
mcp-firewall init                    # Generate starter mcp-firewall.yaml
mcp-firewall init --enterprise       # Generate enterprise policy

# Policy management
mcp-firewall policy validate         # Check policy syntax
mcp-firewall policy test             # Dry-run against test cases
mcp-firewall policy compile          # Show generated Rego

# Dashboard
mcp-firewall wrap --dashboard -- python server.py
mcp-firewall dashboard               # Standalone dashboard (reads audit log)

# Audit
mcp-firewall audit verify            # Verify hash chain integrity
mcp-firewall audit export --format csv --output audit.csv
mcp-firewall audit export --format cef --output siem.log

# Compliance reports
mcp-firewall report dora --output dora-report.pdf
mcp-firewall report finma --output finma-report.pdf
mcp-firewall report soc2 --output soc2-evidence.pdf

# Threat feed
mcp-firewall feed update             # Pull latest rules
mcp-firewall feed list               # Show active rules
mcp-firewall feed add ./my-rule.yaml # Add custom rule

# Scan (integrates mcpwn!)
mcp-firewall scan -- python server.py    # Pre-deployment security scan
```

## Implementation Phases

### Phase 1: Core Proxy + Basic Pipeline (Week 1)
- [ ] stdio proxy (transparent pass-through)
- [ ] Inbound pipeline: kill switch, injection detector, egress control
- [ ] Outbound pipeline: secret scanner, PII detector
- [ ] YAML policy engine (simple rules)
- [ ] JSON audit logger
- [ ] CLI: `wrap`, `init`
- [ ] Tests for all pipeline stages

### Phase 2: Policy Engine + Agent RBAC (Week 2)
- [ ] OPA/Rego integration
- [ ] YAML-to-Rego compiler
- [ ] Agent identity and RBAC
- [ ] Rate limiter (per-agent, per-tool, global)
- [ ] Chain detector
- [ ] Hot-reload policies
- [ ] Human approval flow (terminal prompt)

### Phase 3: Dashboard + Alerting (Week 3)
- [ ] FastAPI + HTMX dashboard
- [ ] Real-time WebSocket feed
- [ ] Historical analytics
- [ ] Alert engine (webhook, Slack, PagerDuty)
- [ ] SSE transport proxy

### Phase 4: Compliance + Threat Feed (Week 4)
- [ ] Signed audit trail (Ed25519 + hash chain)
- [ ] Compliance report generator (DORA, FINMA, SOC2)
- [ ] PDF report generation
- [ ] Threat feed loader + updater
- [ ] Community rules repository
- [ ] mcpwn integration (`mcp-firewall scan`)

### Phase 5: Polish + Launch
- [ ] Documentation site
- [ ] PyPI release
- [ ] GitHub Actions CI/CD
- [ ] CONTRIBUTING.md + SECURITY.md
- [ ] Demo video / GIF
- [ ] Launch: Hacker News, Reddit, LinkedIn, Twitter

## Tech Stack

- **Python 3.11+** (same ecosystem as LlamaFirewall, security tooling)
- **Click** (CLI)
- **FastAPI + HTMX** (Dashboard, no heavy JS)
- **Pydantic** (Models, config validation)
- **OPA/Rego** (Policy engine, via `regopy` or subprocess)
- **Ed25519** (Audit trail signing, via `cryptography`)
- **Rich** (Terminal output)
- **pytest + pytest-asyncio** (Testing)
- **mcp** (Official MCP Python SDK)
- **reportlab** or **weasyprint** (PDF reports)

## Success Metrics

- **1,000 GitHub stars** in first month
- **100 weekly PyPI downloads** in first month
- **3+ conference talk submissions** accepted
- **Featured in** at least 2 security newsletters
- **Enterprise inquiries** from financial institutions
