# Changelog

## 0.2.0a1 — 2026-09-09

First GitHub prerelease of the reviewed firewall and AgentReins integration.
Python wheel and source archives are published on GitHub; this release does not
publish a package to PyPI or a signed/notarized macOS application.

### Added

- Version 1 integration events with session/call/event IDs, sequence numbers,
  sanitized payloads, and explicit decision and observed-outcome fields. SDK
  helpers and migration documentation support embedded callers.
- Authenticated, loopback-only desktop approvals, a browser controller, and a
  native AgentReins controller. Approvals are single-use and bound to the exact
  request; missing/disconnected controllers, expired leases and timeouts deny.
- A development adapter for AgentReins commit
  `dbd4f0abe3ff2d2cd590ac4f7b8e144d7375edbb`, with native event/approval views,
  integration tests against a real Python proxy, and an isolated synthetic demo.
- Opt-in workspace snapshots around admitted, correlated stdio tool calls, with
  authenticated per-file diffs, explicit restore/discard controls, and revision
  and file-identity conflict checks. The native UI exposes the same controls.
- GitHub CI for Python 3.11–3.14 on Linux, Python and native Swift integration on
  macOS, full repository Ruff checks, strict application typing, and isolated
  installs of both release archives. Actions and direct CI tools are pinned.
  Published archives include SHA-256 checksums and CI source identity.

### Fixed

- All 13 reproduced September security review findings: complete outbound text
  traversal/private-key redaction, policy/agent permission composition, address
  normalization and admission-time DNS checks, bidirectional protocol validation,
  subprocess error/lifecycle handling, trusted-key audit verification and writer
  coordination, atomic audit/feed reloads, strict feed loading, bounded rate
  histories, and request/result correlation. See
  [the review implementation](docs/security-fixes-2026-09.md) for scope and tests.
- Existing test lint/format issues so CI checks the entire repository.

### Experimental boundaries

- The firewall observes protocol requests and responses. These do not prove an
  OS side effect or establish trustworthy process identity. MCP client agent
  labels are claims; network redirects/DNS changes still need external network
  enforcement. AgentReins integration does not change these guarantees.
- Recovery is a bounded, in-memory snapshot of one explicitly selected POSIX
  workspace, not a durable backup, process sandbox or multi-file transaction.
  Snapshots disappear when the proxy exits. Missing responses remain incomplete;
  overlapping calls and notifications are denied while snapshots are enabled.
- Restore ordinary file bytes and permissions only. Ownership, ACLs, extended
  attributes and timestamps are not restored; deleted parent directories are not
  recreated. Unsupported links, special files and mount crossings fail closed.
- Pause external writers before restoring. Conflict checks cannot remove the
  final POSIX check-to-write race against an uncooperative editor or background
  task. File contents/diffs are private, unredacted data and stay behind the
  authenticated API; they do not enter public integration events or audit feeds.

See [workspace recovery](docs/workspace-rollback.md),
[desktop approvals](docs/desktop-approvals.md), and
[the AgentReins adapter](integrations/agentreins/README.md) before enabling them.
