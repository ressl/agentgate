# Local dashboard approvals

The dashboard can pause a policy `prompt` decision and let an operator **Allow once**
or **Deny** the exact call. Hard denials remain authoritative, and approval still
runs the remaining pipeline checks. The gateway never executes tools in SDK mode.

## Start a controller

Create a random token in the shell that starts the proxy:

```sh
export MCP_FIREWALL_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
mcp-firewall wrap --dashboard-approvals --approval-timeout 60 -- python my_server.py
```

Open `http://127.0.0.1:9090`, enter the same token into **Controller token**, and
select **Connect** before sending calls requiring approval. On macOS, copy it from
that shell with `printf '%s' "$MCP_FIREWALL_DASHBOARD_TOKEN" | pbcopy`. Clear the
clipboard after pasting. The UI clears the input and retains the token only in
page memory; reconnect after a reload. Do not put tokens in URLs or policy files.

`--dashboard-approvals` implies `--dashboard`. Approval mode accepts only loopback
hosts (`127.0.0.1`, `localhost`, `::1`) and a 32–1024-character ASCII token without
whitespace. Use `--dashboard-port` to choose another port. The credential is removed
from the wrapped MCP server's environment. Plain `--dashboard` remains read-only.

Keep the controller page active: it polls every two seconds and renews a ten-second
lease. Calls requiring approval are denied when no controller is connected, the
lease expires, the request times out, or **Disconnect** is selected. Closing the
page attempts an immediate disconnect; abrupt browser/network loss is detected by
lease expiry. Client EOF and proxy shutdown cancel open approvals immediately.
`--approval-timeout` accepts 1–300 seconds, default 60. Reconnecting cannot revive
an expired or cancelled call. Multiple tabs using the same token share one controller;
disconnecting any tab cancels its pending calls.

## What an approval means

Each pending record has a random ID and a SHA-256 binding over the session ID,
call ID, tool, agent and canonical arguments. A decision consumes that record once.
Changed requests, incorrect hashes and replayed decisions fail closed. Binding
hashes are not encryption; keep the controller API private.

Only the authenticated approval API receives argument previews. Existing event
history and websocket messages do not receive these previews. Known secret/PII
patterns and sensitive argument keys are redacted independently of response-scanning
settings. This is pattern-based scrubbing, not a guarantee that arbitrary sensitive
content can be recognized. Deny calls that cannot be assessed from the preview.
Requests exceeding 16 KiB, individual displayed strings exceeding 1024 characters,
ambiguous redacted keys and nesting deeper than 20 levels are not approvable.
The default maximum is 32 pending records. Oversized or unrepresentable requests
are denied instead of showing a truncated command.

Approval outcomes use the existing correlated human-approval audit entries and
security events. Admission approval is not proof that the tool ran successfully.
The stdio proxy admits calls sequentially; a pending approval delays later client
messages, including MCP cancellation notifications. Closing the client connection
cancels a pending approval. SDK task cancellation is also supported.

This control channel assumes a trusted local operator and trusted same-user processes.
It does not isolate a malicious process running under the operator's OS account.
A [native AgentReins adapter](../integrations/agentreins/README.md) uses this control
channel. Filesystem snapshots and a rollback executor remain separate work.

## Embed the broker

```python
import os

from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.dashboard.server import start_dashboard
from mcp_firewall.sdk import Gateway

broker = ApprovalBroker(timeout_seconds=60, controller_timeout=10, max_pending=32)
start_dashboard(
    approval_broker=broker,
    token=os.environ["MCP_FIREWALL_DASHBOARD_TOKEN"],
)

# Connect the dashboard before the application's calls start.
with Gateway(config_path="mcp-firewall.yaml", approval_broker=broker) as gateway:
    result = gateway.check("read_file", {"path": "reports/summary.md"})
    if result.allowed:
        pass  # The application may execute these same arguments here.

broker.close()
```

Use `await gateway.acheck(...)` in an async application. Cancelling this task cancels
its approval without cancelling another caller's request. `Gateway.close()` wakes
pending approvals before waiting for its policy lock. Closing a Gateway cancels
only its own session; it does not close a shared broker. `auto_approve=True` and
`approval_broker` cannot be combined. Broker operations do not bypass global policies.

The existing dashboard has one controller configuration per process. Custom native
adapters may call `broker.pending()` to renew the lease, display its sanitized
`PendingApproval` values, then call `broker.decide(id, request_hash, allow)`.
Those methods are trusted in-process APIs: an adapter exposing them over a transport
must authenticate its operator and protect that transport itself.

## HTTP contract

Control requests require `Authorization: Bearer <token>`. Browser origins must
match the local request origin; foreign hosts/origins are rejected. Tokens in
query parameters are not accepted. Responses use `Cache-Control: no-store`.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/approval-mode` | Public capability flag, no request details |
| `GET /api/approvals` | Authenticated pending list and lease renewal |
| `POST /api/approvals/{id}` | Consume one decision |
| `POST /api/approvals/disconnect` | Drop the lease and deny pending calls |

Decision bodies must be JSON, at most 1024 bytes, with exactly these fields:

```json
{"request_hash": "<64 lowercase hexadecimal characters>", "allow": true}
```

`allow` must be a boolean. Success returns `{"accepted": true}`. Invalid bodies
return 400, invalid authentication 401, foreign origins/hosts 403, disabled control
404, stale/changed/mismatched decisions 409, oversized bodies 413, and unsupported
content types 415. A 409 never approves a call; fetch the current pending list.
