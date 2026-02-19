# Threat Feed

Community-maintained detection rules for known attack patterns.

## Built-in Rules

| ID | Name | Severity | Description |
|---|---|---|---|
| TF-001 | Webhook Exfiltration | High | Detects data exfil to webhook.site, requestbin, ngrok, etc. |
| TF-002 | DNS Tunneling | Critical | Detects DNS-based data exfiltration (burpcollaborator, dnslog) |
| TF-003 | Credential Harvesting | Critical | Detects reads of .ssh/id_*, .aws/credentials, .env, shadow |
| TF-004 | Cloud Metadata SSRF | Critical | Detects access to 169.254.169.254 and metadata endpoints |
| TF-005 | Reverse Shell | Critical | Detects bash -i, /dev/tcp, nc -e, and other reverse shells |

## List Rules

```bash
mcp-firewall feed list
```

## Writing Custom Rules

Create a YAML file:

```yaml
# my-rules/block-internal-api.yaml
id: CUSTOM-001
name: Block Internal API
severity: high
description: Block access to internal corporate API
tags: [custom, internal]
match:
  arguments:
    url: "*internal-api.corp.local*"
action: deny
```

### Rule Schema

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Unique rule identifier |
| `name` | Yes | Human-readable name |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, `info` |
| `description` | No | What this rule detects |
| `match` | Yes | Matching criteria |
| `match.arguments` | No | Argument pattern matching (glob-style) |
| `match.tool` | No | Tool name pattern |
| `action` | No | `deny` (default), `alert` |
| `tags` | No | Categorization tags |

### Pattern Matching

- `*webhook.site*` — contains "webhook.site"
- `*.ssh/id_*` — SSH private keys
- `*foo*|*bar*` — multiple alternatives (OR)

## Contributing Rules

Submit rules via pull request to the mcp-firewall repository:

1. Create a YAML file in `mcp-firewall/threatfeed/rules/`
2. Follow the naming: `<category>-<description>.yaml`
3. Include comprehensive match patterns
4. Test against example inputs
5. Submit PR
