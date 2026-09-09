# Policy Reference

## Configuration File

mcp-firewall uses `mcp-firewall.yaml` for policy configuration. Generate a starter config:

```bash
mcp-firewall init                # Starter config (defaultAction: prompt)
mcp-firewall init --enterprise   # Stricter template: deny-by-default, high
                                 # injection sensitivity, PII detection, 60 calls/min
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

Agent permissions and global rules both apply. An agent allowlist does not bypass
global argument restrictions: the first matching global deny still blocks the
call. An agent approval requirement survives a global allow, and a global deny
takes precedence over approval. If no global rule matches, an explicit agent
allow or approval requirement takes precedence over `defaultAction`.
Allowed calls still pass through chain detection.

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

**Note:** Interactive approval requires a terminal. In non-interactive sessions — the normal case when an MCP client spawns the proxy over stdio — `prompt` decisions fail closed and the call is denied.

## Injection Detection Sensitivity

| Level | Patterns | False Positive Rate |
|---|---|---|
| `low` | 5 critical patterns | Very low |
| `medium` | 13 patterns (default) | Low |
| `high` | 18+ patterns incl. Unicode | Medium |

## Reloading Configuration

The proxy does not watch the config file — restart `mcp-firewall wrap` to apply changes. SDK users can reload at runtime without restarting their agent:

```python
gw.reload()  # Re-reads mcp-firewall.yaml, rebuilds alert channels and threat feed rules
```

Reload also applies audit enablement, path, signing, and size limits. An invalid
enabled threat feed rejects the reload and leaves the previous configuration
active. Changing audit signing mode starts a new log generation linked to the
archived generation; see [audit integrity](compliance.md#audit-trail-integrity).
Per-agent rate history is retained only for configured limits. Newly enabled
agent limits begin with the calls observed after they are enabled.

## Egress checks and response scanning

Egress checks normalize private IPv4/IPv6 literals, localhost names, and trailing
DNS dots. Hostnames in URLs and network fields such as `host` are resolved and
every returned address is checked. Lookup failures deny the call while address
protection is enabled. Async proxy lookups run outside the protocol event loop
with a three-second wait limit. Arguments exceeding the inspection depth are
denied rather than partially inspected.

These checks inspect arguments before forwarding them. They do not control the
server's sockets, later DNS changes, redirects, or destinations constructed by
arbitrary server code. Use an operating-system/container network policy or a
controlled network proxy when actual connection-level isolation is required.

Secret and PII scanners cover text inside content blocks (including embedded
resources), structured output, and result extension fields. All copies are
redacted; denial returns a replacement result containing no original payload.
Redaction can change structured values and keys, so redacted output may no longer
conform to a server's original output schema. Excessive nesting, cycles, and key
collisions caused by redaction block the result. Private-key redaction removes
the complete block; an unterminated private-key block consumes the remaining text.
