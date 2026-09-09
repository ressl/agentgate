# Integration events and SDK embedding

Approved scope: the first implementation package discussed in issue #2: shared
events, safe SDK defaults, and a documented webhook adapter. Desktop approvals,
pre-execution snapshot acknowledgements, and rollback are follow-up work.

## Contract

A versioned, immutable SecurityEvent carries a generated event ID, session ID,
internal call ID, optional protocol request ID, per-session sequence number,
timestamp, phase, tool/agent labels, action, severity, and sanitized reason.
Phases distinguish reception, policy findings, admission, actual forwarding,
response reception/scanning, and unknown outcomes. Forwarding does not prove
execution or filesystem attribution. Missing lifecycle evidence stays unknown.

Raw arguments, output, and arbitrary decision details are excluded. Text fields
are bounded and scrubbed for known credentials and PII even when response scanners
are disabled. This is pattern-based redaction, not a promise to identify every
secret. Stable opaque call IDs provide correlation without exporting arguments.

Pipeline decision audit entries embed the same event format and preserve existing
chain/signature verification. The dashboard consumes final decision events through
an adapter, preserving its existing call/response counting semantics. Intermediate
lifecycle observations do not inflate decision audit or dashboard counts.

## Delivery

An optional events configuration enables a generic HTTP webhook. A bounded queue
and one background worker keep network latency outside admission/response checks.
Stable event IDs support receiver deduplication. HTTP requests have timeouts,
bounded retries for transient failures, no redirects, and no implicit environment
proxy. Authentication uses operator-configured headers. Failures and dropped events
are exposed through counters and sanitized diagnostics. Delivery is best-effort,
in memory, and never grants permission or proves a pre-execution snapshot exists.

SDK callbacks use the same bounded dispatcher. Arbitrary callbacks are trusted
application code and must finish promptly; Python cannot forcibly stop a blocked
callback. Shutdown has a bounded wait and reports undelivered work.

Existing alert channel configuration remains compatible. New lifecycle events
are opt-in and use a distinct versioned envelope.

## SDK

Auto-approval defaults to false; explicit audit configuration is respected.
Check results include an immutable correlation context. Text and structured scans
accept that context; scans without it are explicitly uncorrelated observations.
Async APIs run blocking pipeline work outside the caller's event loop and serialize
shared pipeline state. Async cancellation must not report forwarding or execution.
Explicit close/context-manager APIs flush delivery within a deadline and release
resources. Configuration reload preserves session identity and custom observers.

## Verification and rollout

Regression tests cover phase ordering and parallel correlation, safe default
approval, audit configuration and signature compatibility, nested response scanning,
privacy with disabled scanners, queue overflow, retries/deduplication, failed/slow
observers, shutdown, and interrupted proxy calls. A runnable loopback-only sample
receiver checks authentication, schema, size limits, and event deduplication.

Document event JSON schema, examples, failure semantics, and SDK migration. Native
tests, Ruff, strict mypy, package build, and an installed-wheel smoke validate the
result. No package release or production deployment is part of this change.

## Implementation checklist

- [x] Inspect current code and confirm the approved first-package scope.
- [x] Compare minimal existing-webhook use, generic integration, and full sidecar
  control; choose the generic event interface described above.
- [x] Review this design for missing boundaries and contradictory guarantees.
- [ ] Implement event models, sanitization, delivery, and configuration.
- [ ] Connect pipeline, decision audit, proxy lifecycle, and dashboard adapter.
- [ ] Implement SDK contexts, safe defaults, async APIs, and cleanup.
- [ ] Add adapter example, schema, migration documentation, and regressions.
- [ ] Run checks and record the verified outcome.

The referenced writing-plans and test-driven-development skills are unavailable in
the installed skill roots. This checklist and focused regression-first checks are
the local workflow fallback. User approval of the presented design was given before
implementation; this document records that approved scope.
