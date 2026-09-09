# Desktop approvals through the existing dashboard

Continue with the next proposed stage: authenticated, one-call human approvals.
The event/SDK foundation is merged in PR #4. Snapshot/rollback execution and an
AgentReins-specific adapter are outside this stage.

Use the current dashboard as the first controller instead of adding a native app.
A reusable in-process ApprovalBroker also exposes the same request/decision flow
to SDK callers and other local controller adapters.

## Security and lifecycle

- Only policy PROMPT decisions enter the broker. Global denial and later pipeline
  stages remain authoritative. Approval never executes a tool itself.
- A request has a generated approval ID and SHA-256 binding over session, call,
  tool, agent, and canonical arguments. Approval is single-use; changed arguments,
  expired requests, and mismatched bindings cannot be approved.
- Pending records, argument previews, and wait duration are bounded. Preview text
  is scrubbed for credentials and PII; oversized/unrepresentable requests deny.
- A controller must be connected and renew a short lease by polling. Missing or
  expired controller lease, explicit disconnect, shutdown, timeout, or cancellation
  denies pending calls. Reconnecting cannot resurrect expired requests.
- SDK/proxy admission waits off the event loop. Pending approvals can be cancelled
  during shutdown before waiting for policy locks.
- Admission and approval outcomes retain existing correlated audit/event behavior.

## Interface and UI

`wrap --dashboard-approvals` enables the existing dashboard plus the broker, and
requires a random token from MCP_FIREWALL_DASHBOARD_TOKEN. Approval mode binds only
to loopback. The token is not printed, sent in a URL, or stored by the browser.
The dashboard presents a password input and Connect/Disconnect actions, then shows
pending tool calls with sanitized arguments and Allow once/Deny buttons.

Dedicated approval API endpoints require Bearer authentication, reject foreign
browser origins/hosts, return no-store responses, and accept strict JSON decisions.
The token is entered by the operator and held only in page memory. UI strings use
textContent; sensitive previews never enter the public event websocket/history.

The broker is an optional public Gateway constructor argument. SDK consumers can
use it with the same local dashboard or another authenticated controller adapter.
Auto-approval and broker-based approval cannot be configured together.

## Validation checklist

- [x] Inspect existing approval, proxy, SDK, dashboard, and CLI boundaries.
- [x] Record the selected existing-dashboard approach and scope.
- [ ] Reproduce required nonce/hash/timeout/disconnect/cancellation behavior in tests.
- [ ] Implement broker, pipeline/SDK hooks, authenticated API, CLI, and UI.
- [ ] Validate no policy bypass, no secret exposure, and bounded pending requests.
- [ ] Test real HTTP/stdio approval and browser UI behavior.
- [ ] Document setup and limits; run tests, lint/type checks, and package validation.
