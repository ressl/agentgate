# Scoped workspace snapshots and selective rollback

The user approved a native adapter smoke test followed by scoped file snapshots,
change inspection and selective undo that protects subsequent user edits.

## Chosen scope

One explicitly configured local POSIX workspace per stdio proxy, enabled with
`--snapshot-workspace PATH` alongside authenticated dashboard approvals. Capture
all regular files immediately before forwarding each admitted tool call; capture
again on its correlated response, including error or blocked responses. Policy
and human denials never create a snapshot or execute a tool. Refuse overlapping
calls and notifications in snapshot mode. This is observation of a time interval,
not proof that the tool caused each change or that background work has stopped.

Snapshots stay in memory for the proxy lifetime: at most 8 records, 1000 files,
2 MiB per file, 16 MiB per capture, 128 MiB retained. Reserve capacity for the
post-call capture before forwarding. Never silently evict recovery records;
explicitly discard a completed record to release capacity. No durable content
storage is introduced. Exclude `.git`, `.venv`, `node_modules`, `__pycache__` and
`.DS_Store` at every depth. Exclusions and unsupported entries are visible in docs.
Symlinks, hard-linked files, special files, mount crossings and unstable captures
fail closed rather than following paths outside the scope. Root and parent
identities are checked using directory descriptors and no-follow operations.

## Review and restore

Authenticated, no-store endpoints expose bounded record metadata, a selected
file's literal text diff and an opaque revision token. Binary/large text previews
are marked omitted; exact bytes are retained for restoring. File content is
private to the authenticated controller and is never added to public events,
webhooks, audit or AgentReins EventStore. Preview is explicitly local sensitive
content; no claim of complete secret redaction.

Native UI shows snapshot status, changed files, individual diffs and an explicit
restore confirmation. Restore takes a single selected file and the reviewed
record revision. It requires no tool in flight, a complete post-call snapshot,
and the file/parent identity, bytes, mode and modification metadata to match the
recorded post-call state. Stale revisions, later edits, symlinks or changed roots
produce a conflict with no overwrite. Each successful restore advances the
revision and is visibly recorded. Replays fail. Discard also binds the revision.

Restore regular-file content and POSIX permission bits only; added files can be
removed and deleted files restored when their parent still exists unchanged.
Do not recreate deleted directory trees, modify symlinks, restore xattrs/ACLs or
claim a multi-file transaction. Use same-directory temporary files and atomic
replacement with immediate revalidation. External writers must be paused:
POSIX does not provide a portable compare-and-swap for path replacement, so an
uncooperative writer racing the final check is outside this first version's
transaction guarantees. Refuse restore while tracked calls are in flight.

A missing response or failed post-capture marks the record incomplete and makes
it unrestorable. A connection loss cannot prove the tool/background work stopped.
No automatic rollback, process attribution, sandboxing or external-action undo.

## Alternatives considered

- Git reset/stash: rejected because it risks index/user work and misses untracked
  file semantics; this feature must also work without Git.
- Persistent content-addressed backups: useful later, but needs a separate private
  storage, retention and crash-recovery design.
- Bounded in-memory snapshots: chosen for an explicit, testable first version.

## Native practice test

Use the real adapter view/controller compiled in the pinned AgentReins package,
with an isolated demo app entry point and synthetic local MCP server. This avoids
starting unrelated process/file/history monitors and touching personal history or
preferences. Operate native Connect, Allow once, Deny, Disconnect and sheet Close;
then inspect and restore a synthetic file and demonstrate a later-edit conflict.
Clearly distinguish this demo UI test from exercising all upstream monitoring UI.

## Implementation and verification plan

1. Add a reusable, locked snapshot engine with bounded descriptor-based capture,
   stable fingerprints, diff/revision views and selected-file restore/discard.
2. Wire opt-in CLI, stdio lifecycle and protected controller routes.
3. Extend native adapter client/models/view with review and explicit restore.
4. Provide a reproducible isolated native demo and operate it with UI automation.
5. Test modified/added/deleted/binary files, permissions, later edits, stale and
   concurrent requests, links/path traversal/root replacement, resource bounds,
   interrupted calls, policy denials, auth/no-store and actual Swift/proxy flow.
6. Run Python suites, Ruff/mypy, pinned Swift suites, package/wheel smoke, inspect
   diff and secrets; commit, push and merge under existing session authorization.

Design reviewed inline for scope, consistency and testability. The user's existing
approval covers this milestone. The writing-plans skill is not installed in the
shared or Codex skill roots; the ordered plan above is the local fallback.

## Outcome

Implemented the scoped snapshot engine, protected API, stdio admission/correlation,
native review/restore/discard and isolated demo. Native clicks verified approval,
denial, disconnect, diff, confirmed restore, later-edit conflict and discard on
synthetic files. Snapshot labels gained timestamps and call-ID prefixes.
Regression checks also caught and fixed missing-newline diff rendering and a
missing audit denial when snapshot admission blocks an earlier policy allow.
The final denial uses the existing policy stage and leaves event schema v1 intact.

Validation: 475 Python tests on 3.11/3.14, 9 adapter tests including live Swift/proxy
recovery, 18 existing upstream tests, Ruff and strict mypy. The exact retained
limits and filesystem race/metadata boundaries are documented in
`docs/workspace-rollback.md`. No upstream release or multi-file transaction.
