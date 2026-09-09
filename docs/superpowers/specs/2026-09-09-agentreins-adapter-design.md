# AgentReins adapter and end-to-end verification

Continue the user-approved next stage: connect actual AgentReins to the existing
firewall, test approval, denial, response inspection and disconnect. Snapshot and
rollback work follows this integration milestone.

## Approach

Use the existing authenticated loopback dashboard API. Add a bounded pull event
feed so a Swift client needs no inbound HTTP server. Alternatives were a separate
webhook-to-file bridge (an extra daemon and sensitive file lifecycle) or Unix-domain
sockets (a second control transport). HTTP reuses the reviewed approval boundary.

The Python feed retains at most 1000 sanitized SecurityEvent records. It returns
an opaque stream ID, increasing cursor, explicit retention gap, and at most 256
records per read. A stream ID change forces a reconnect; event polling alone does
not renew the approval controller lease. Existing public dashboard feeds remain
unchanged. No raw arguments or results enter the event feed.

Own Swift adapter sources live in integrations/agentreins. A checked installer
applies them to a clean, explicitly selected AgentReins checkout pinned to
 dbd4f0abe3ff2d2cd590ac4f7b8e144d7375edbb. Do not vendor upstream sources. Build and
test against its actual GuardEvent and AgentSessionSnapshot implementations.

The Swift client accepts loopback HTTP endpoints, disables redirects/proxies/cookies
and caches, keeps credentials in memory, caps response bytes, validates schema and
cursor ordering, and reports disconnect/retention loss. A main-actor adapter polls
outside UI work, exposes pending requests, and records GuardEvent projections via
onEvents. Session IDs are namespaced by firewall; absent turn/workspace/model data
stay absent. Final response statuses never claim verified execution or file effects.
Single-use approval sends the exact ID/hash from the pending view; stale decisions
refresh the list and never turn into a new approval. No automatic Allow behavior.

A native SwiftUI pane offers Connect/Disconnect and Allow once/Deny. It is attached
to the real AgentReins app through the small installation patch. Adapter event
observations are not fed into its filesystem recovery executor.

## Validation and implementation checklist

- [x] Inspect current upstream source, actual event model and local toolchain.
- [x] Select transport, evidence semantics, safety boundaries and isolated checkout.
- [ ] Add Python authenticated feed tests and implement bounded replay.
- [ ] Add Swift parsing/transport/projection tests and implement native adapter/UI.
- [ ] Compile actual AgentReins with the adapter; run isolated integration tests.
- [ ] Run actual Python stdio proxy and Swift adapter together, proving call gating,
      response redaction, explicit denial, lost connection and stale approvals.
- [ ] Document reproducible setup, verified upstream commit and remaining limits.
- [ ] Run Python compatibility tests, lint/types, package checks; commit/push/merge.
