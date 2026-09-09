# Scoped workspace snapshots and file rollback

mcp-firewall can capture a local workspace before forwarding a tool call, compare
it after the correlated response, and restore a selected file after native review.
Enable this explicitly; the default proxy behavior does not capture files.

```sh
export MCP_FIREWALL_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
mcp-firewall wrap --dashboard-approvals --snapshot-workspace /absolute/project \
  -- python my_workspace_server.py
```

Use the [native AgentReins adapter](../integrations/agentreins/README.md). Connect
the controller, allow an appropriate call, then open **Review snapshot**, choose
**View diff**, and select **Restore this file…**. Review the confirmation before
restoring. The browser approval pane does not provide snapshot recovery controls.

Snapshots observe changes during a call's time interval. They do not prove which
process caused a change, stop a server writing elsewhere, or undo network/API
side effects. A server can still perform background work after responding.

## Capture and limits

One canonical workspace is configured per stdio proxy. It works without Git and
does not alter the Git index. Every admitted `tools/call` is captured, including
apparently read-only tools; the proxy does not infer filesystem safety from tool
names or supplied paths. Policy/human denials create no snapshot. Snapshot-mode
notifications without a request ID and overlapping tool calls are denied before
forwarding. Snapshot admission refusals emit and audit a final deny under the
existing `policy` stage with a workspace admission reason, including refusals after
an earlier policy allow. The integration-event v1 schema remains unchanged. Other MCP messages
retain their normal behavior.

The post-call capture runs when a correlated response arrives, including protocol
errors, malformed tool results and responses subsequently blocked or redacted.
If capture fails or the connection ends without a response, the record is marked
**incomplete** and cannot be restored. Neither a complete snapshot nor a passed
response proves successful tool execution or stopped background work.

| Limit | First version |
| --- | --- |
| Retention | Proxy process lifetime; at most 8 records |
| Retained file bytes | 128 MiB total; post-capture capacity reserved before forwarding |
| Each capture | 16 MiB total, 2 MiB per file, 1000 directory entries |
| Paths | 32 components, 1024 UTF-8 bytes, no control/format characters |
| Capture consistency | Two matching scans; cooperative 10-second budget between filesystem operations |
| Preview | UTF-8 text up to 64 KiB and 2000 newlines per side; generated diff at most 64 KiB |

Limits are fixed in this first version. Captures include regular files owned by
the proxy user with ordinary permission bits. Symlinks, hard-linked files, special
files, set-ID/sticky file modes, mount crossings and unstable captures are refused.
The configured path is canonicalized at startup; the resulting root identity is
pinned. Descendants are traversed using directory descriptors and no-follow opens.
This requires POSIX, tested on macOS; Windows snapshot mode is unsupported.

At every depth, `.git`, `.venv`, `node_modules`, `__pycache__` and `.DS_Store` are
excluded, including links with these names. Their contents and directory metadata
are not backed up or restored. Large generated trees may require a smaller scope.
Do not put a continuously changing audit log inside the selected workspace.

Records are never silently evicted. Use **Discard…** and confirm to release a
completed/incomplete record's recovery bytes. A full store blocks further tool
admission until space is released. Discard changes no workspace files. Closing
the native sheet keeps the controller connected; disconnecting the controller
leaves snapshots available for an explicit reconnect while the proxy runs. Exiting
the proxy loses them. This is not a durable backup or crash recovery system.

## Selective restore and conflict protection

A restore request names one opaque snapshot ID, one opaque file ID, and the exact
revision returned by the reviewed preview. A successful restore changes that
revision. Replays and stale confirmations fail. Snapshot list responses omit file
names and contents; individual detail/preview requests retrieve them on demand.

Restore requires a complete post-capture and no active tracked tool call. The root
and parent identities, current file bytes, identity, link count, mode, size,
modification time and change time must match the recorded post-call state. A later
edit, replacement, chmod, symlink or changed/missing parent produces a conflict.
Restoring one file does not authorize restoring other files.

- A modified file is replaced with its original bytes and POSIX permission bits.
- An added regular file is removed if it still matches the post-capture.
- A deleted regular file is recreated if its parent is unchanged and the target
  is still absent. An exclusive link operation prevents overwriting a concurrently
  recreated file.
- Deleted directories are not recreated; empty new directories remain. Ownership,
  timestamps, ACLs, xattrs and filesystem flags are not restored. Replacement can
  lose existing extended metadata: use this feature for ordinary project files,
  not metadata-sensitive documents.

Content is staged in a randomly named file inside the checked parent and synced
before atomic replacement. The path chain and target are rechecked immediately
before mutation. A stale UI must never refresh its revision and retry a restore
automatically. On a transport failure the result may be unknown: inspect the file
and refreshed record before another action.

**Pause all external writers before restoring.** The proxy prevents its own tool
calls overlapping recovery; it cannot lock out editors, other agents or background
server tasks. POSIX replacement/unlink lacks a portable conditional operation on
the exact observed file identity. A writer racing the final check can therefore
still be overwritten. This first version provides conservative stale-edit checks
and atomic per-file replacement, not a sandbox or a multi-file transaction.

## Privacy and local API

Before/after bytes are held in process memory. A restore temporarily stages the
selected original file in its existing workspace directory. No persistent backup
store is created. Snapshot bytes, paths and diffs do not enter public dashboard
events, webhooks, audit events, or AgentReins' `EventStore`/recovery executor.

File previews are sensitive local content, **not redacted**. Only the authenticated
controller can fetch them. Text is displayed literally, without Markdown/HTML
rendering. Binary or oversized previews are explicitly omitted; their bounded
original bytes remain available for a deliberately confirmed restore. The native
adapter clears workspace details on disconnect and never persists them itself.

These routes use the approval controller's bearer token, loopback and same-origin
checks and `Cache-Control: no-store`. Reads never renew the approval lease.

| Route | Result |
| --- | --- |
| `GET /api/workspace` | Enabled state, canonical root, busy flag and up to 8 record summaries |
| `GET /api/workspace/{snapshot_id}` | Record metadata and changed file IDs/paths/kinds/restored flags |
| `GET /api/workspace/{snapshot_id}/files/{file_id}` | Bounded diff, omitted flag and reviewed revision |
| `POST /api/workspace/{snapshot_id}/files/{file_id}/restore` | Restore one file; JSON `{"revision":"<uuid>"}` |
| `POST /api/workspace/{snapshot_id}/discard` | Release one completed/incomplete record; same JSON revision |

Actions require `application/json`, reject unknown fields and limit bodies to 256
bytes. Conflicts return 409 without reflecting arbitrary submitted data. When
snapshots are disabled, the authenticated list reports `enabled: false`; actions
return 404. `WorkspaceSnapshots` can be reused directly with a trusted local
controller, but automatic lifecycle wiring is currently supplied only for stdio.

## Reproducible native practice test

After installing the adapter into a dedicated pinned checkout:

```sh
python integrations/agentreins/demo.py ../AgentReins-firewall --snapshots
```

The helper compiles the real adapter in a temporary copy of the AgentReins package
with an isolated demo app entry point. It does not start upstream OS/history
monitors. It launches a synthetic local MCP server and temporary workspace and
prints a local URL and a **public fixture-only credential**. Never reuse that
credential for a real controller. The app uses a separate demo bundle identity.

1. Enter the printed URL/fixture token and select **Connect**.
2. Enter `write` in the helper terminal, then choose **Allow once** in the app.
3. Open the newest snapshot and diff. Confirm **Restore this file…**; `inspect`
   in the helper terminal shows the original content.
4. Enter `write` again and allow it. Open its new diff, then enter `edit-user` in
   the terminal. Confirming restore now shows a conflict; `inspect` proves that
   the later edit was preserved.
5. Try `deny` plus native **Deny**, or `disconnect` plus native **Disconnect**.
   Neither request should appear in the executed-call log printed by `inspect`.
6. Enter `quit` to stop the owned demo processes and remove temporary fixtures.

The automated equivalent is `python integrations/agentreins/verify.py CHECKOUT`.
It covers the real Swift controller and HTTP/stdio boundaries, including redaction,
replay, lease loss, restore and later-edit conflict. The native click test also
checks the actual SwiftUI view and confirmation dialogs; it is not a test of all
upstream AgentReins monitoring screens or an upstream release.
