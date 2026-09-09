# AgentReins native adapter

Connect AgentReins to the existing local mcp-firewall controller. The adapter adds
an **MCP Firewall** toolbar button with native **Connect**, **Allow once**, **Deny**
and **Disconnect** controls, plus optional workspace snapshot review and file restore. Sanitized lifecycle events enter AgentReins' actual
`GuardEvent`/`EventStore` flow and a dedicated evidence view.

This directory contains our adapter sources and a checked installer. It does not
vendor AgentReins or claim an upstream release. Compatibility is pinned to
[`yardfribley-bit/AgentReins` at `dbd4f0a`](https://github.com/yardfribley-bit/AgentReins/tree/dbd4f0abe3ff2d2cd590ac4f7b8e144d7375edbb).
Newer upstream revisions need review before updating the installer pin.

## Install into a development checkout

Requirements: macOS 13+, Swift 6 toolchain, Git, Python 3.11+, and the mcp-firewall
source checkout with its dependencies installed. Run these commands from that
firewall checkout. In an activated Python virtual environment, install the current
source with `python -m pip install -e ".[dev]"`. Choose a new directory for AgentReins:

```sh
git clone https://github.com/yardfribley-bit/AgentReins.git ../AgentReins-firewall
git -C ../AgentReins-firewall checkout dbd4f0abe3ff2d2cd590ac4f7b8e144d7375edbb
python integrations/agentreins/install.py ../AgentReins-firewall
swift test --package-path ../AgentReins-firewall --filter MCPFirewallAdapterTests
```

The installer requires the exact clean checkout and refuses to overwrite adapter
files or existing edits. It copies `Sources/*.swift`, installs the tests, and adds
three wiring points to `AgentGuardApp.swift`. Source-specific guards in
`AgentSession.swift`, `SecurityIncident.swift`, `DevelopmentTrace.swift` and
`ContentView.swift` keep protocol outcomes from being shown as completed execution
or verified process attribution. Existing agent sources retain their behavior. Review with
`git -C ../AgentReins-firewall diff`. Keep this dedicated checkout for the demo;
no existing AgentReins installation or user preferences are modified by the installer.
The Swift sources are distributed in this repository/source archive, not the Python wheel.

Start the MCP proxy with the [dashboard approval setup](../../docs/desktop-approvals.md):

```sh
export MCP_FIREWALL_DASHBOARD_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
mcp-firewall wrap --dashboard-approvals -- python my_server.py
```

Then run the instrumented application:

```sh
swift run --package-path ../AgentReins-firewall AgentReins
```

Open **MCP Firewall** in the toolbar, enter `http://127.0.0.1:9090` and the controller
token, and select **Connect** before sending calls that require approval. On macOS,
copy the token from the launching shell using
`printf '%s' "$MCP_FIREWALL_DASHBOARD_TOKEN" | pbcopy`, then clear the clipboard.
The token field clears on connect and the adapter keeps the token only in memory.
It never stores credentials in UserDefaults, files or URLs.

AgentReins' existing process/file/Codex/WorkBuddy behavior remains its own application
behavior. The adapter does not start those monitors during its isolated tests.
Closing the adapter sheet keeps the explicitly connected controller active while
AgentReins runs. Use **Disconnect** to stop it. Quitting/crashing the application
loses its lease, causing pending approvals to deny within ten seconds.

## Reproduce the real integration test

```sh
python integrations/agentreins/verify.py ../AgentReins-firewall
```

The harness starts a real mcp-firewall stdio proxy, real HTTP control endpoints and
an isolated toy MCP server. It runs the Swift tests inside the actual AgentReins
package, using `MCPFirewallSight`, `MCPFirewallClient`, `GuardEvent` and
`AgentSessionSnapshot`. It does not launch AgentReins' monitoring app or read user
agent histories. Temporary fixtures and child processes are cleaned up.

The test verifies:

- Wrong credentials cannot connect; a call waits until native approval.
- Exactly one approved request reaches the toy server, which cannot inherit the token.
- Its response contains a synthetic AWS key that the firewall removes.
- Existing incident/development views do not promote blocked responses into completed
  tool execution or verified process identity.
- The response projection says **execution unverified**, with no invented model output,
  user turn, workspace path, process identity or recovery evidence.
- Replaying a consumed approval fails; hard policy denial and user denial never forward.
- Explicit disconnect and abrupt controller loss deny pending calls.
- Snapshot diffs, native single-file restore, replay rejection and later-edit conflicts
  use the actual proxy workspace; file content never enters projected events.
- Redirects and oversized HTTP responses are rejected; malformed schemas and cursors fail.

Running `swift test` alone skips the two live tests because their private fixture
addresses and credentials are supplied only by `verify.py`.

## Native snapshot practice test

Enable `--snapshot-workspace /absolute/project` alongside `--dashboard-approvals`
to capture admitted calls and review individual file changes. See the
[setup, boundaries and API](../../docs/workspace-rollback.md) before use: snapshots
are bounded and live only as long as the proxy; external writers must be paused
for restore. File diffs contain sensitive local content and are not redacted.

To exercise the actual native view with synthetic files and no OS/history monitors:

```sh
python integrations/agentreins/demo.py ../AgentReins-firewall --snapshots
```

Use its printed local URL and fixture-only token. Enter `write` in the terminal,
allow it in the app, inspect its diff, and confirm restore. Repeat with `edit-user`
after opening the next diff to demonstrate conflict protection. Enter `quit` to
clean up. Never use the public demo credential with a real workspace.

## Evidence and control boundaries

The optional authenticated feed is enabled with dashboard approvals. It retains
1000 sanitized events in memory and returns at most 256 per page. Polling events
alone does not renew the approval lease. Native control polls every two seconds;
the client uses three-second request/five-second resource timeouts and a 4 MiB
response cap. Redirects, cookies, caches and configured HTTP proxies are disabled.

The adapter keeps 200 events for its dedicated view and 10,000 event IDs for
in-memory deduplication. AgentReins applies its existing event-store retention to
projected events. A retention gap or missing per-session sequence produces a visible
incomplete-evidence warning. A changed stream ID stops the connection and requires
explicit reconnect. There is no durable event replay or exactly-once delivery.

Firewall session IDs are namespaced as `mcp-firewall:<uuid>` and are **not** joined
to a Codex/WorkBuddy turn by agent name or timestamp. MCP request IDs remain distinct
from tool-call UUIDs. Uncorrelated responses have no projected tool-call ID. Tool
arguments and output are absent from activity events; sanitized approval previews
remain transient and are not recorded in `EventStore`.

Permission observations are intermediate decisions. A response block can occur
*after* side effects. Neither a passed response nor a captured protocol result
proves successful execution, file changes, or safe rollback. This adapter does not
feed observations into AgentReins' recovery executor. The optional
[workspace snapshot controller](../../docs/workspace-rollback.md) independently observes
file changes and provides explicitly confirmed single-file restore with conflict checks.
It does not provide a multi-file transaction or automatic rollback. Stdio admission is still sequential:
queued MCP cancellation notifications wait behind approval, while client EOF and
SDK cancellation cancel pending approvals immediately.

Use one controller per proxy. The native pane and browser dashboard share the same
controller lease when connected concurrently; either can disconnect pending calls.
This is a trusted-user, local IPC boundary, not isolation from hostile processes
running under the same macOS account.

## Verified on 2026-09-09

- Python 3.11 and 3.14: 475 firewall tests passed.
- Swift 6.3.3 on arm64 macOS: all nine adapter tests passed, including both live tests.
- The 18 existing AgentReins tests passed. The full Swift suite skips the two live
  tests when fixture environment variables are absent; `verify.py` executes them.
- Fresh-checkout installation and full AgentReins compilation passed.
- Ruff, strict mypy, staged Gitleaks, source/wheel builds and an isolated Python 3.11
  installed-wheel check passed. The archive includes Swift sources; the wheel retains
  the firewall modules and bundled threat rules.

The isolated native demo was also operated through its real SwiftUI controls:
Connect, Allow once, Deny, Disconnect, Close, diff review, confirmed file restore,
later-edit conflict and confirmed discard. The restored bytes and preserved later
edit were checked directly in the synthetic workspace. Snapshot rows include time
and a call-ID prefix to distinguish repeated calls.

The full monitoring app was compiled but not launched against personal agent histories.
No AgentReins upstream release or notarized app distribution is claimed. Recovery
is bounded and per file; persistent backups and multi-file transactions remain out
of scope.
