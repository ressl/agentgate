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
| Policy-as-Code | YAML | Python | ❌ | **YAML** |
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
2. **YAML Policy-as-Code**: Versionable, reviewable policies — no code changes needed
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
└─────────────┘     │  └──────────┘  │   (YAML)  │  └───────────┘ │
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
- Transparent stdio proxy (SSE/Streamable HTTP planned)
- Zero-config wrapping of any MCP server
- Agent identity extraction from the `initialize` handshake (`clientInfo.name`)

### 2. Inbound Pipeline (`mcp-firewall/pipeline/inbound/`)
Sequential checks on every `tools/call` request:

| Stage | Check | Action |
|---|---|---|
| 1 | **Kill Switch** | Emergency deny-all (file trigger, signal) |
| 2 | **Rate Limiter** | Per-agent, per-tool, global limits |
| 3 | **Injection Detector** | Prompt injection patterns (sensitivity: low/medium/high) |
| 4 | **Egress Control** | Block private IPs, cloud metadata, SSRF |
| 5 | **Threat Feed** | Known attack patterns (built-in community rules) |
| 6 | **Policy Engine** | YAML rules + per-agent RBAC (agent identity from the initialize handshake) |
| 7 | **Chain Detector** | Detect dangerous tool sequences |

When a stage returns `prompt`, **Human Approval** asks the user in the terminal;
non-interactive sessions fail closed (deny). The threat feed runs before the
policy engine so that permissive allow rules cannot override known-malicious
patterns.

### 3. Outbound Pipeline (`mcp-firewall/pipeline/outbound/`)
Scans every tool response:

| Stage | Check | Action |
|---|---|---|
| 1 | **Secret Scanner** | API keys, tokens, private keys, passwords |
| 2 | **PII Detector** | Email, phone, SSN, credit cards, IBAN |

Actions: `pass` | `redact` | `deny` | `alert`

### 4. Policy Engine (`mcp-firewall/pipeline/inbound/policy.py`)
- **YAML rules**: First-match-wins rules with glob argument matching
- **Agent RBAC**: Per-agent allow/deny/require_approval lists
- **Built-in policies**: Sensible defaults that block 90% of attacks
- **Runtime reload**: SDK callers can reload policies without restart (`Gateway.reload()`)

Example policy:
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

Report format: Markdown (importable into any documentation or GRC system)

### 7. Dashboard (`mcp-firewall/dashboard/`)
- Real-time WebSocket event feed
- Statistics (tool usage, block rates, latency)
- Agent activity overview
- Built with: FastAPI + vanilla JS (no heavy JS framework)

### 8. Alert Engine (`mcp-firewall/alerts/`)
- Slack (webhook)
- Generic webhook (with custom headers)
- Syslog / SIEM integration (CEF)
- Alert rule: severity threshold (`minSeverity`)

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

- Built-in rules shipped with the package (`mcp_firewall/threatfeed/rules/`)
- Custom rules directory via `threatFeed.feedDir`
- Community contributions via PR

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
│   │   │   ├── rate_limiter.py
│   │   │   ├── injection.py
│   │   │   ├── egress.py
│   │   │   ├── threat_feed.py
│   │   │   ├── policy.py
│   │   │   ├── chain_detector.py
│   │   │   └── human_approval.py
│   │   └── outbound/
│   │       ├── __init__.py
│   │       ├── secrets.py
│   │       └── pii.py
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
mcp-firewall init --enterprise       # Generate enterprise policy (deny-by-default)

# Validate config
mcp-firewall validate --config mcp-firewall.yaml

# Dashboard (runs alongside the proxy)
mcp-firewall wrap --dashboard -- python server.py
mcp-firewall wrap --dashboard --dashboard-port 8080 -- python server.py

# Audit
mcp-firewall audit                   # Verify hash chain integrity

# Compliance reports (Markdown)
mcp-firewall report dora --output dora-report.md
mcp-firewall report finma --output finma-report.md
mcp-firewall report soc2 --output soc2-evidence.md

# Threat feed
mcp-firewall feed list                       # Show active rules
mcp-firewall feed list --rules-dir ./my-rules  # Include custom rules

# Scan (integrates mcpwn!)
mcp-firewall scan -- python server.py    # Pre-deployment security scan
```

Planned (not yet implemented): standalone `dashboard` command (reads audit log),
`audit export` (CSV/CEF), `feed update` / `feed add` (rule distribution),
SSE/Streamable HTTP transport.

## Implementation Phases

### Phase 1: Core Proxy + Basic Pipeline (Week 1)
- [x] stdio proxy (transparent pass-through)
- [x] Inbound pipeline: kill switch, injection detector, egress control
- [x] Outbound pipeline: secret scanner, PII detector
- [x] YAML policy engine (simple rules)
- [x] JSON audit logger
- [x] CLI: `wrap`, `init`
- [x] Tests for all pipeline stages

### Phase 2: Policy Engine + Agent RBAC (Week 2)
- [x] YAML policy engine with glob matching (no OPA/Rego — pure YAML rules)
- [x] Agent identity (from the MCP `initialize` handshake) and RBAC
- [x] Rate limiter (per-agent, per-tool, global)
- [x] Chain detector
- [x] Runtime config reload via SDK (`Gateway.reload()`)
- [x] Human approval flow (terminal prompt, fail-closed when non-interactive)

### Phase 3: Dashboard + Alerting (Week 3)
- [x] FastAPI dashboard (vanilla JS)
- [x] Real-time WebSocket feed
- [ ] Historical analytics
- [x] Alert engine (Slack, generic webhook, syslog)
- [ ] SSE transport proxy

### Phase 4: Compliance + Threat Feed (Week 4)
- [x] Signed audit trail (Ed25519 + hash chain)
- [x] Compliance report generator (DORA, FINMA, SOC2)
- [x] Markdown report generation (PDF planned)
- [x] Threat feed loader (built-in rules + `threatFeed.feedDir`)
- [ ] Feed updater + community rules repository
- [x] mcpwn integration (`mcp-firewall scan`)

### Phase 5: Polish + Launch
- [ ] Documentation site
- [ ] PyPI release
- [ ] GitHub Actions CI/CD
- [x] CONTRIBUTING.md + SECURITY.md
- [ ] Demo video / GIF
- [ ] Launch: Hacker News, Reddit, LinkedIn, Twitter

## Tech Stack

- **Python 3.11+** (same ecosystem as LlamaFirewall, security tooling)
- **Click** (CLI)
- **FastAPI** (Dashboard, no heavy JS)
- **Pydantic** (Models, config validation)
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
