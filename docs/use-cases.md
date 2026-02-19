# Use Cases & Real-World Examples

## Wer nutzt MCP Server heute?

### 1. Entwickler mit Claude Desktop

Claude Desktop (Anthropic) war der erste MCP Client. Millionen Entwickler nutzen es täglich mit MCP Servern für Dateizugriff, GitHub, Datenbanken etc.

**Konfiguration ohne mcp-firewall:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/Users/dev/projects"]
    },
    "github": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_xxxx" }
    }
  }
}
```

**Problem:** Claude hat vollen Zugriff auf dein Dateisystem und deinen GitHub Token. Ein Prompt Injection Angriff (z.B. in einer gelesenen Datei) kann Claude dazu bringen, deine SSH Keys zu lesen und per HTTP POST rauszuschicken.

**Mit mcp-firewall:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-firewall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"]
    },
    "github": {
      "command": "mcp-firewall",
      "args": ["wrap", "--", "npx", "@modelcontextprotocol/server-github"]
    }
  }
}
```

Jetzt blockiert mcp-firewall:
- Zugriff auf `.ssh/`, `.env`, `.aws/` Dateien
- Prompt Injection Versuche in Tool-Argumenten
- Exfiltration von Secrets in Antworten
- Gefährliche Tool-Ketten (read_file + http_post)

---

### 2. Cursor / Windsurf / VS Code (AI Coding Assistants)

Cursor und ähnliche AI-IDEs nutzen MCP um dem AI-Agenten Zugriff auf das Projekt, Terminal, und externe APIs zu geben.

**Typisches Setup:**
```json
{
  "mcpServers": {
    "project-db": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-sqlite", "./production.db"]
    },
    "deploy": {
      "command": "python",
      "args": ["mcp_deploy_server.py"]
    }
  }
}
```

**Risiko:** Der AI Agent hat Zugriff auf die Produktionsdatenbank und kann Deployments triggern. Ein bösartiger MCP Server oder eine Prompt Injection kann Daten exfiltrieren oder ungewollte Deployments starten.

**Mit mcp-firewall:**
```yaml
# mcp-firewall.yaml
agents:
  cursor:
    allow: [query, read_file, search]
    deny: [deploy, exec, drop_table, delete]
    require_approval: [write_file, insert, update]
    rate_limit: "100/min"
```

---

### 3. Unternehmen mit internen MCP Servern

Firmen bauen eigene MCP Server für interne Tools: CRM, ERP, Ticketing, Monitoring.

**Beispiel: Bank mit internem MCP Server**
```
Claude Desktop → MCP Server "banking-tools"
                    ├── check_balance(account_id)
                    ├── create_transfer(from, to, amount)
                    ├── list_transactions(account_id, days)
                    └── generate_report(type, period)
```

**Regulatorische Anforderung (DORA/FINMA):**
- Jeder Tool-Aufruf muss geloggt werden
- Zugriff auf sensible Operationen braucht Genehmigung
- Audit Trail muss manipulationssicher sein
- Regelmässige Compliance Reports

**mcp-firewall löst das:**
```yaml
# mcp-firewall.yaml (Enterprise Policy)
defaultAction: deny

agents:
  analyst-claude:
    allow: [check_balance, list_transactions, generate_report]
    deny: [create_transfer]
    rate_limit: "50/min"

  manager-claude:
    allow: [check_balance, list_transactions, generate_report]
    require_approval: [create_transfer]
    rate_limit: "20/min"

audit:
  enabled: true
  sign: true  # Ed25519 signiert
  path: /var/log/mcp-firewall/banking-audit.jsonl
```

```bash
# Quartals-Compliance-Report
mcp-firewall report dora --audit-log /var/log/mcp-firewall/banking-audit.jsonl --output Q1-2026-DORA.md
mcp-firewall report finma --audit-log /var/log/mcp-firewall/banking-audit.jsonl --output Q1-2026-FINMA.md
```

---

### 4. Security Teams (Red Team / Blue Team)

**Red Team:** Nutzt `mcpwn` um MCP Server zu scannen und Schwachstellen zu finden.

```bash
# Scan vor dem Deployment
mcpwn scan --stdio "python internal_mcp_server.py"
# → 3 critical, 5 high findings
```

**Blue Team:** Deployt `mcp-firewall` als Runtime-Schutz.

```bash
# Schutz zur Laufzeit
mcp-firewall wrap --dashboard -- python internal_mcp_server.py
# → Dashboard zeigt alle blocked Attacks live
```

**SOC (Security Operations Center):** Integriert mcp-firewall mit SIEM.

```yaml
# Alerts an Splunk/Elastic via Syslog CEF
alerts:
  - channel: syslog
    host: siem.corp.local
    port: 514
    min_severity: high
```

---

### 5. Open Source MCP Server Maintainer

Du baust einen MCP Server und willst zeigen, dass er sicher ist.

```bash
# In deiner CI/CD Pipeline
pip install mcpwn
mcpwn scan --stdio "python my_server.py" --format json --output scan.json
mcpwn check --input scan.json --fail-on high
# Exit Code 0 = keine kritischen Findings → grüner Build
```

Und empfiehlst deinen Usern:
```
# README.md
## Security
We recommend running this server behind [mcp-firewall](https://github.com/ressl/mcp-firewall)
for additional runtime protection.
```

---

## Zusammenfassung: Wer braucht was?

| Zielgruppe | Tool | Warum |
|---|---|---|
| **Entwickler** (Claude Desktop, Cursor) | mcp-firewall | Schutz vor bösartigen/fehlerhaften MCP Servern |
| **Security Teams** | mcpwn + mcp-firewall | Scan + Schutz, SIEM Integration |
| **Compliance Officers** (DORA, FINMA, SOC2) | mcp-firewall | Audit Trail, Reports, Nachweispflicht |
| **CISOs** | mcp-firewall | Visibility, Policy Enforcement, Dashboard |
| **MCP Server Entwickler** | mcpwn | CI/CD Security Scanning |
| **Red Teamer** | mcpwn | Schwachstellen finden |
| **Regulated Industries** (Banking, Insurance) | mcp-firewall | Pflicht durch DORA Art. 9+11, FINMA |

## Konkrete Produkte die MCP nutzen

| Produkt | Typ | MCP Support |
|---|---|---|
| Claude Desktop | AI Assistant | ✅ Nativ (Anthropic hat MCP erfunden) |
| Claude Code | CLI Coding Agent | ✅ |
| Cursor | AI Code Editor | ✅ |
| Windsurf (Codeium) | AI Code Editor | ✅ |
| VS Code + Copilot | IDE | ✅ (via Extension) |
| Zed | Code Editor | ✅ |
| Amazon Q Developer | AI Assistant | ✅ |
| Sourcegraph Cody | Code AI | ✅ |
| JetBrains AI | IDE Plugin | ✅ |
| Continue.dev | AI Coding | ✅ |
| OpenAI Agents SDK | Framework | ✅ |
| LangChain | Framework | ✅ |
| Spring AI (Java) | Framework | ✅ |
