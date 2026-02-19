# Getting Started

## Installation

```bash
pip install mcp-firewall
```

## Quick Start

### 1. Wrap any MCP server

```bash
mcp-firewall wrap -- npx @modelcontextprotocol/server-filesystem /tmp
```

That's it. mcp-firewall now intercepts every tool call, scans for threats, and enforces default security policies.

### 2. Generate a config

```bash
mcp-firewall init
```

This creates `mcp-firewall.yaml` with sensible defaults:
- Blocks SSH key access
- Blocks .env file access
- Requires approval for shell commands
- Allows file reads
- Rate limits at 200 calls/minute

### 3. Customize policies

Edit `mcp-firewall.yaml`:

```yaml
agents:
  claude-desktop:
    allow: [read_file, search]
    deny: [exec, shell, rm]
    rate_limit: "100/min"

rules:
  - name: block-credentials
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
```

### 4. Enable the dashboard

```bash
mcp-firewall wrap --dashboard -- python my_server.py
# Dashboard at http://127.0.0.1:9090
```

### 5. Use with Claude Desktop

Replace your MCP server config:

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

## Features at a Glance

| Command | Description |
|---|---|
| `mcp-firewall wrap -- <server>` | Wrap and protect an MCP server |
| `mcp-firewall wrap --dashboard -- <server>` | With real-time dashboard |
| `mcp-firewall init` | Generate starter config |
| `mcp-firewall validate` | Check config syntax |
| `mcp-firewall audit` | Verify audit log integrity |
| `mcp-firewall scan -- <server>` | Pre-deployment security scan |
| `mcp-firewall report dora` | DORA compliance report |
| `mcp-firewall report finma` | FINMA compliance report |
| `mcp-firewall report soc2` | SOC 2 evidence report |
| `mcp-firewall feed list` | List threat feed rules |

## Next Steps

- [Policy Reference](policies.md) — Full policy configuration guide
- [Compliance Guide](compliance.md) — Regulatory report generation
- [Threat Feed](threat-feed.md) — Community detection rules
- [Architecture](../ARCHITECTURE.md) — Technical deep dive
