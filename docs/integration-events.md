# Integration events, schema version 1

The optional event stream connects mcp-firewall to desktop companions, IDEs, and
other observers. It reports what the gateway observed. It cannot attribute file
changes, establish a snapshot before execution, or undo side effects.

## Enable a webhook

```yaml
events:
  enabled: true
  queueSize: 256
  shutdownTimeout: 5
  webhook:
    url: http://127.0.0.1:8766/events
    timeoutSeconds: 2
    maxRetries: 2
    headers:
      Authorization: "Bearer <your-random-receiver-token>"
```

Snake-case field names also work. Event export is off by default. Enabling HTTP
export without a webhook URL is rejected. Keep receiver credentials in an
operator-managed configuration file with restricted permissions;
do not commit them. YAML header values are literal: `${NAME}` is not expanded.
Use HTTPS for remote endpoints. The sender validates TLS normally, does not follow
redirects, and ignores environment HTTP proxies. It does not log URLs, headers,
response bodies, or exception text on delivery failure.

The existing `alerts:` configuration remains a separate, severity-filtered
notification interface using its existing `{"source": ..., "alert": ...}` shape.
`events:` sends lifecycle observations without alert severity/action filtering.
Enabling both can produce both notifications and events for the same decision;
avoid configuring both to the same receiver unless it handles both formats.

## Wire format and correlation

Requests are JSON HTTP POSTs with this envelope:

```json
{
  "source": "mcp-firewall",
  "event": {
    "schema_version": 1,
    "id": "d547b9ba-ec07-4081-a5a5-c5da5baf9021",
    "session_id": "37f7cf17-2f4a-4625-98b9-8f992b846381",
    "call_id": "f442e98a-7dd7-49a2-b415-2dac7dc6cb4c",
    "request_id": 1,
    "correlated": true,
    "sequence": 3,
    "timestamp": 1788940800.0,
    "phase": "request_allowed",
    "response_is_error": null,
    "tool": "status",
    "agent": "desktop-client",
    "action": "allow",
    "severity": "info",
    "stage": null,
    "reason": ""
  }
}
```

The complete [JSON schema](integration-events.schema.json) is generated from
`EventEnvelope.model_json_schema()`. Additive fields or changed semantics require
an explicit version policy; receivers should reject unsupported schema versions.

- `id` identifies one event, including every retry. `Idempotency-Key` equals this ID.
- `session_id` identifies one proxy or SDK Gateway instance. It survives SDK reload.
- `call_id` is a generated identifier for one tool call, independent of MCP IDs.
- `request_id` preserves the protocol ID's integer/string distinction when present.
  Sensitive or oversized string IDs are scrubbed; correlate using `call_id`.
- `sequence` increases within a session. Gaps can indicate missing delivery.
- `correlated: false` marks an unmatched proxy response or an SDK scan without its
  original context. Do not infer a matching request from a similar tool name.
- `agent` is an informational label supplied by the client/caller, not authenticated
  identity. A call context is correlation metadata, not an authorization token.

## Lifecycle semantics

| Phase | Meaning |
| --- | --- |
| `request_received` | A valid tool call entered admission checks. |
| `policy_decision` | An audited policy/approval observation; later stages may still deny. |
| `request_allowed` | Admission completed. The gateway has not established execution. |
| `request_denied` | Admission denied the call; the proxy does not forward it. |
| `request_forwarded` | The proxy queued the request to the server's stdin pipe; not proof of receipt or execution. |
| `response_received` | A response was observed (or supplied to the SDK). |
| `response_finding` | A response scanning stage produced an audited finding. |
| `response_allowed` | Scanning allowed the response; this does not mean the tool succeeded. |
| `response_redacted` | The response was modified to remove detected sensitive text. |
| `response_denied` | The response was blocked, including unscannable/malformed results. |
| `response_error` | The server returned a JSON-RPC error. |
| `request_unknown` | Admission/scanning was interrupted or a connection ended without a complete response. |

`response_is_error` preserves the tool result's `isError` flag on response
reception/final scan events. Missing or null means no such flag is represented.
Neither an allowed response nor a server-reported result proves host-side effects.

A blocked response can follow an already executed operation. Never use response
denial as proof that no changes occurred. Unparseable protocol input may not be
attributable; an outstanding call then remains incomplete until disconnect.
Tool notifications without response IDs have unknown outcomes after forwarding.

SDK APIs never emit `request_forwarded`: executing the tool remains the host
application's responsibility. A cancelled async SDK wait does not stop a running
Python worker or resolver; admission events may still arrive afterward.

## Delivery, loss, and shutdown

Each emitter uses one lazy background worker and a bounded queue. A slow receiver
does not block admission or scanning. The same immutable event is delivered to SDK
callbacks and the configured webhook. Queued events are processed in sequence.
Callbacks must be synchronous and return promptly; they execute on the worker,
not on the caller's event loop. Exceptions are isolated from policy decisions.

The HTTP sender retries transport errors, HTTP 429, and HTTP 5xx, up to
`maxRetries` (0–3). Other failures, including redirects and authentication failures,
are not retried. It reads only the response status/headers and closes the body.
`timeoutSeconds` is the HTTP I/O timeout, not an end-to-end execution deadline.
A successful HTTP status only acknowledges receipt by the receiver.

Delivery is **best-effort and in memory**. A full queue drops the newly offered
event; exhausted retries mark the event failed. Process termination may lose queued
events. Receivers must deduplicate by event ID and handle missing sequences.
The stream has no replay protocol or exactly-once guarantee.

`Gateway.delivery_stats` exposes `enqueued`, `delivered`, `failed`, `dropped`,
`queued`, and `in_flight`. Delivery counts apply to events: failure of any configured
observer marks that event failed even if another observer received it. Counters
survive successful event configuration reloads. Sanitized warnings report failures,
queue overflow, and incomplete shutdown; these do not grant access or change policy.

`close()` / `aclose()` drain event delivery up to `shutdownTimeout` (0–30 seconds),
then discard queued work. A callback already running may finish later; Python cannot
forcibly kill arbitrary callback code. Closing a Gateway also waits for any currently
running SDK operation to release its policy-state lock. Use async cleanup from an
async application. The proxy terminates its child before waiting for event delivery.

Changing event transport/queue settings during SDK reload requires event delivery
to be idle; otherwise reload raises `ValueError` and retains the previous settings.
Retry after `queued` and `in_flight` reach zero. Reloading other settings without
changing `events:` does not replace or interrupt the dispatcher.

## Privacy and existing consumers

Events exclude raw arguments, response content, and arbitrary decision details.
Tool/agent labels, protocol string IDs, and free-text reasons are scrubbed for known
secret and PII patterns even when response scanning is disabled. Oversized fields
are omitted wholesale. Detection is pattern-based and cannot identify every secret;
do not use labels or rule messages to carry confidential data.

Decision audit rows embed the same sanitized object under `event`. Existing audit
fields and hash/signature verification remain supported. Intermediate lifecycle
observations are not additional audit decision rows. The dashboard adapts final
admission/response decisions from the same model, preserving its call/response
counters. Legacy alert channels also receive scrubbed labels/reasons and no raw
arguments or decision details.

## Example receiver

[examples/event_receiver.py](../examples/event_receiver.py) listens on
`127.0.0.1:8766`, requires a Bearer token, validates the envelope and delivery ID,
limits bodies to 64 KiB, and remembers the latest 10,000 event IDs in memory.
Deduplication is limited to that window and resets on restart. It logs only phases
and opaque IDs and performs no workspace actions.

Install the project in your environment, set `MCP_FIREWALL_RECEIVER_TOKEN` to a
random value of at least 32 characters, and start:

```sh
python examples/event_receiver.py
```

Configure the sender with the same token. A production receiver should add request
deadlines, durable deduplication if needed, and its own retention policy.

For an in-process integration:

```python
from mcp_firewall.models import SecurityEvent
from mcp_firewall.sdk import Gateway

def on_event(event: SecurityEvent) -> None:
    print(event.call_id, event.phase.value)  # Runs on the delivery worker

with Gateway(config_path="mcp-firewall.yaml", event_handler=on_event) as gateway:
    decision = gateway.check("status")
    if decision.allowed:
        gateway.scan_response("example output", context=decision.context)

print(gateway.delivery_stats)
```

`event_handler` works independently of the `events.enabled` HTTP export switch.
See [SDK migration](sdk-migration.md) for asynchronous and structured usage.
