# Policy Reference

## Configuration File

mcp-firewall uses `mcp-firewall.yaml` for policy configuration. Generate a starter config:

```bash
mcp-firewall init
```

## Structure

```yaml
version: 1
defaultAction: prompt    # allow | deny | prompt

globalRateLimit:
  maxCalls: 200
  windowSeconds: 60

security:
  injectionDetection:
    enabled: true
    sensitivity: medium  # low | medium | high
  egressControl:
    enabled: true
    blockPrivateIPs: true
    blockCloudMetadata: true

responseScanning:
  detectSecrets: true
  detectPII: false

agents: {}               # Per-agent RBAC
rules: []                # Policy rules

audit:
  enabled: true
  path: mcp-firewall.audit.jsonl
  sign: false            # Ed25519 signing
```

## Agent RBAC

Define per-agent access policies:

```yaml
agents:
  claude-desktop:
    allow: [read_file, search, list_directory]
    deny: [exec, shell, rm, delete]
    rate_limit: "100/min"
    require_approval: [write_file]

  cursor:
    allow: [read_file, write_file, search]
    deny: [http_post, fetch_url]
    rate_limit: "200/min"
```

**Logic:**
1. `deny` is checked first (always blocks)
2. `require_approval` prompts the user
3. `allow` explicitly permits
4. If `allow` list exists but tool is not in it, the call is denied

## Rules

Rules are evaluated in order (first match wins):

```yaml
rules:
  # Block credential access
  - name: block-ssh-keys
    tool: "*"
    match:
      arguments:
        path: "**/.ssh/**"
    action: deny
    message: "SSH key access blocked"

  # Require approval for shell
  - name: approve-shell
    tool: "shell_exec|run_command|bash"
    action: prompt

  # Allow safe reads
  - name: allow-reads
    tool: "read_file|list_directory"
    action: allow

  # Rate limit API calls
  - name: limit-api
    tool: "fetch|http_*"
    action: allow
    rate_limit:
      maxCalls: 50
      windowSeconds: 60
```

### Rule Fields

| Field | Description |
|---|---|
| `name` | Rule name (for logging) |
| `tool` | Tool pattern (`*` for all, `foo\|bar` for multiple) |
| `match.arguments` | Argument pattern matching (`**` glob) |
| `action` | `allow`, `deny`, or `prompt` |
| `message` | Custom denial message |
| `rate_limit` | Per-rule rate limit |

### Argument Matching

Patterns support glob-style matching:

- `**/.ssh/**` — matches any path containing `.ssh/`
- `*.env*` — matches `.env`, `.env.local`, etc.
- `**/secrets/**` — matches any path containing `secrets/`

## Default Action

When no rule matches:
- `allow` — permit the call (least restrictive)
- `deny` — block the call (most restrictive)
- `prompt` — ask the user (recommended)

## Injection Detection Sensitivity

| Level | Patterns | False Positive Rate |
|---|---|---|
| `low` | 5 critical patterns | Very low |
| `medium` | 13 patterns (default) | Low |
| `high` | 18+ patterns incl. Unicode | Medium |

## Hot Reload

Edit `mcp-firewall.yaml` while the proxy is running. Changes are applied on the next tool call.
