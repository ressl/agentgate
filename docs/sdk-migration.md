# SDK migration: integration update (unreleased)

This update changes security defaults. Review callers before upgrading an embedded
deployment. Optional [local desktop approvals](desktop-approvals.md) are now available;
automatic filesystem recovery remains outside this update.

## Approval and audit defaults

`Gateway` now defaults to `auto_approve=False`. A policy requiring user approval
fails closed in SDK mode unless an authenticated controller is connected through
an explicitly supplied `ApprovalBroker`. SDK mode has no terminal prompt. Configure an
explicit allow policy for intended operations. Applications that deliberately want
the previous approval behavior can pass `auto_approve=True`; this only satisfies
approval requirements and does not bypass global denials or other pipeline stages.

Audit configuration is always respected, including explicit configuration files
and a discovered `mcp-firewall.yaml`. Without a file, normal defaults enable audit
logging to `mcp-firewall.audit.jsonl`. To disable it intentionally, set
`audit.enabled: false`. Passing a configuration object no longer allows Gateway
construction to mutate that caller-owned object.

Supplying both `config` and `config_path` is rejected. `reload()` without a path
reuses the original explicit path (if any). Reload keeps session identity and
registered observers. Invalid replacement configuration leaves the old one active.

## Retain call context

`check()` returns a `CheckResult` whose `.context` contains immutable session/call
IDs and a digest of the arguments. Pass it into the matching scan:

```python
from mcp_firewall.sdk import Gateway

with Gateway(config_path="mcp-firewall.yaml") as gateway:
    decision = gateway.check("status", {}, agent="my-agent")
    if decision.allowed:
        # Execute the actual tool in your application here.
        output = "illustrative tool output"
        result = gateway.scan_response(output, context=decision.context)
        if not result.blocked:
            print(result.content)
```

A context from another Gateway or a denied check is rejected. It is not a permission
token and does not authenticate the caller or prove execution. The argument digest
allows matching audit rows without retaining raw arguments in the context; it is
not encryption and should not be treated as a secrecy guarantee for low-entropy data.

The existing text API `scan_response(content, tool_name=..., agent=...)` still works.
Without a context, its events are marked `correlated: false`. The returned
`ScanResult` remains an object with `.content`, `.modified`, `.findings`, and `.blocked`.

## Async and complete tool responses

```python
from mcp_firewall.models import ToolCallResponse
from mcp_firewall.sdk import Gateway

async def inspect_example():
    async with Gateway(config_path="mcp-firewall.yaml") as gateway:
        decision = await gateway.acheck("status")
        if decision.blocked:
            return None
        response = ToolCallResponse(
            request_id="",  # Correlation comes from decision.context
            content=[{"type": "text", "text": "example output"}],
            structured_content={"status": "ok"},
            extra_fields={"_meta": {"description": "example metadata"}},
        )
        scanned = await gateway.ascan_tool_response(response, context=decision.context)
        return None if scanned.blocked else scanned.response
```

`scan_tool_response()` and `ascan_tool_response()` return `StructuredScanResult`.
They scan embedded resources, structured content, and result extensions as well
as text blocks. A denied result has empty content/metadata and `is_error=True`.
Scanning works on a copy, preserving the caller's response object.

`acheck`, `ascan_response`, `ascan_tool_response`, `areload`, and `aclose` run blocking
operations outside the caller's event loop. One Gateway serializes policy access;
concurrent checks still receive distinct call IDs. Cancelling a wait cannot forcibly
cancel a running Python worker or system DNS lookup. An open broker approval for
the cancelled check is revoked. The SDK never executes tools.

## Resource lifetime

Prefer `with` or `async with`. Otherwise call `close()` / `await aclose()` to flush
bounded event delivery and close resources. Calls after close raise `RuntimeError`.
Callbacks execute in a worker thread; marshal UI updates onto your GUI's own thread.
See [event delivery semantics](integration-events.md#delivery-loss-and-shutdown)
for timeout, failure, queue, and reload behavior.
