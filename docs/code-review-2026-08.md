# Code Review — August 2026

Full-codebase review of mcp-firewall (~3,400 LOC). Every finding was verified by reading the
relevant code; several were additionally confirmed empirically (Python 3.14).

Severity: **high** = protection feature ineffective or service-disrupting in practice,
**medium** = concrete bypass or wrong behavior under realistic conditions,
**low** = robustness, correctness, and documentation issues.

Findings are numbered `H<n>` / `M<n>` / `L<n>`; the fix status is tracked in the last column.

---

## High

### H1 — Human approval fails open in non-interactive environments
`pipeline/inbound/human_approval.py:45`
When `sys.stderr` is not a TTY (the normal case when an MCP client spawns the proxy), every
`prompt` decision silently becomes ALLOW ("Non-interactive, auto-approved"). Since
`defaultAction: prompt` is the documented default, the firewall effectively runs fail-open.
The non-interactive fallback must be DENY (or configurable).

### H2 — `input()` reads from the JSON-RPC stream and blocks the event loop
`pipeline/inbound/human_approval.py:64`, `proxy/stdio.py:82`
In the TTY case, `HumanApproval` calls synchronous `input()` on **stdin** — the same file
descriptor that asyncio concurrently reads as the MCP protocol channel. This blocks the whole
event loop and races with protocol messages. Approval must run off the event loop and must not
consume stdin.

### H3 — Proxy crash (DoS) on non-dict JSON; task exceptions swallowed
`proxy/stdio.py:145,214`, `proxy/stdio.py:61-67`
`json.loads("123")` returns an `int`; `msg.get(...)` then raises `AttributeError`.
`ToolCallRequest(...)` raises `ValidationError` when `params.arguments` is not a mapping. The
exception propagates out of the intercept task, and `asyncio.wait(FIRST_COMPLETED)` shuts down
the entire proxy — one malformed message kills the firewall. `done` is never inspected, so the
error is never even logged.

### H4 — Agent RBAC is dead in proxy mode
`proxy/stdio.py:152-156`, `pipeline/inbound/policy.py:28`, `pipeline/inbound/chain_detector.py:73`
The proxy never sets `agent_id` (always `"unknown"`); the `initialize` handshake (`clientInfo`)
is not evaluated. All `agents:` rules (allow/deny/require_approval) never fire in proxy mode,
and the `ChainDetector` mixes the history of all agents under one key.

### H5 — Alerts and threat feed are never wired into the pipeline
`alerts/engine.py`, `pipeline/runner.py`, `cli.py:194`
`AlertEngine` is never instantiated outside tests; `ThreatFeed.check()` is only called by
`feed list`, never in the request pipeline. README and `docs/use-cases.md` advertise both as
active features, including an `alerts:` config section that does not exist.

### H6 — Glob→Regex conversion without escaping; invalid patterns fail open
`threatfeed/loader.py:44,47,53,77`, `pipeline/inbound/policy.py:122-124`
- Shipped rule TF-003 (`*.env`) matches `/home/user/venv` (unescaped `.`) → benign paths are
  denied as *critical credential harvesting*. Missing `$` anchor lets `*.pem` match `key.pemx`.
- `loader.py:47` swallows `re.error` silently; a rule with an uncompilable pattern then matches
  **every** request (fail-open deny-all / or match-all).
- Non-string argument values bypass the matcher entirely (`loader.py:77`).
- `fnmatch.translate()` is the correct primitive (and `fnmatch` is already imported).

### H7 — Dashboard WebSocket broadcast runs on the wrong event loop
`dashboard/app.py:60-64`, `dashboard/server.py:12-18`, `proxy/stdio.py:165,199`
`add_event()` is called from the proxy loop, but `loop.create_task(self._broadcast(...))`
schedules `ws.send_json()` for sockets owned by the uvicorn loop in another thread. The first
exception marks every client "dead" and removes it — the live feed is silently broken.
Fix: `loop.call_soon_threadsafe()` onto the uvicorn loop (plus locking for shared state).

### H8 — Stored XSS in the dashboard
`dashboard/app.py:212-219`
`evt.tool`, `evt.agent`, and `evt.reason` are interpolated unescaped via `innerHTML`.
`evt.tool` comes straight from the client request — i.e. from exactly the untrusted agent the
firewall is supposed to monitor. Use `textContent` / DOM APIs instead.

---

## Medium

### M1 — Egress control: multiple SSRF bypasses
`pipeline/inbound/egress.py`
- `_extract_urls` only extracts `http(s)://` and `file://` from embedded text; the dangerous
  schemes `gopher/dict/ftp/ldap` are never extracted, so the scheme check is dead for them.
- The direct-value `startswith` check is case-sensitive (`GOPHER://…` bypasses it).
- Bare IPs as argument values (`{"host": "169.254.169.254"}`) are never checked.
- IPv4 short forms (`127.1`) and octal dotted forms (`0177.0.0.1`) raise `ValueError` in
  `ipaddress.ip_address` and bypass the check; curl/browsers resolve them to `127.0.0.1`.
- Recursion depth > 5 and lists-in-lists are not searched — URLs can be hidden there.

### M2 — camelCase config keys are silently dropped
`config.py:46-48`, `models.py:127-155`
`egressControl` / `killSwitch` raw dicts are passed to pydantic models whose fields are
snake_case; pydantic v2 drops extra keys silently. `blockPrivateIPs: false` and
`killSwitch.filePath` — exactly the keys the generated example config and docs show — have no
effect.

### M3 — Rule rate limits with glob patterns never fire
`pipeline/inbound/rate_limiter.py:113-117`
`_tool_matches_simple` does exact comparison only; the documented example `tool: "fetch|http_*"`
never matches. `rule.match.arguments` is also ignored when rate-limiting.

### M4 — Outbound enforcement stops at the first REDACT decision
`proxy/stdio.py:232-243`
The loop returns on the first DENY *or* REDACT decision. If `SecretScanner` yields REDACT and a
later stage (e.g. PII with `action: deny`) yields DENY, the deny is never enforced.

### M5 — `scan_response` DENY returns the original content including the secret
`sdk.py:163-164`
`modified` is only set for REDACT. With `secrets.action: deny`, `ScanResult` returns the
unchanged text (with the secret) and `modified=False`; the block only appears in `findings`.

### M6 — Unbounded buffers and maps
`proxy/stdio.py:90-94,114-117` (read buffer without size limit → memory exhaustion),
`pipeline/inbound/chain_detector.py:68`, `pipeline/inbound/rate_limiter.py:44-46,96`,
`dashboard/app.py:53-55` (dicts keyed by attacker-controlled tool/agent names, never evicted).

### M7 — Audit hash chain is not thread-safe
`audit/logger.py:68`
`self._previous_hash` is read (and the event signed) **before** the lock; only the write is
protected. Concurrent `log()` calls can read the same `previous_hash` and append out of order —
the chain breaks despite the "thread-safe" promise.

### M8 — `audit.max_size_mb` is never enforced
`models.py:197` defines it; no code references it. The audit log grows without bound.

### M9 — Missing config file silently falls back to defaults
`cli.py:26`, `config.py:20-21`
`wrap --config typo.yaml`: `click.Path()` without `exists=True`; `load_config` silently returns
defaults. The firewall runs with the default policy while the user believes their policy loaded.
(`validate` correctly uses `exists=True` — inconsistent.)

### M10 — Normal shutdown yields exit code 241
`proxy/stdio.py:76`, `cli.py:63`
On client disconnect the server is terminated → `returncode == -15` → `sys.exit(-15)` →
shell exit status 241 instead of 0.

### M11 — Dashboard counts double/triple; `limit=0` returns everything
`dashboard/app.py:106-107,114-117` + JS in `app.py:223-247`
Server stats + REST replay + WebSocket replay are all accumulated → counters are inflated right
after page load and the last 20 events appear twice. `events[-0:]` returns the full buffer;
negative limits bypass the cap. Missing `Query(ge=1)` validation.

### M12 — KillSwitch crashes outside the main thread; clobbers existing handler
`pipeline/inbound/kill_switch.py:35-37`
`signal.signal()` raises `ValueError` in worker threads; only `OSError`/`AttributeError` are
caught. Registration also overwrites any pre-existing SIGUSR1 handler of the host application.

### M13 — Missing mcpwn is reported as "high findings"
`scanner.py:14,18-22`, `cli.py:130-139`
Via `sys.executable -m mcpwn`, a missing module never raises `FileNotFoundError`; the
interpreter exits with code 1 → interpreted as "high findings". The friendly install hint is
dead code. `" ".join(server_args)` also destroys quoting (use `shlex.join` / list form).

### M14 — "always" approval is global and irreversible
`pipeline/inbound/human_approval.py:70-72`
One "always" sets `_auto_approve = True` for **all** future tool calls of **all** agents for the
process lifetime. Users expect "always for this tool".

### M15 — Alerts can be silently lost
`alerts/engine.py:94`
`asyncio.get_event_loop().create_task(...)`: with a set-but-not-running loop the task is created
on a loop that never runs — the alert is never sent, and the RuntimeError fallback does not
fire. Task exceptions are never retrieved. Use `asyncio.get_running_loop()`.

### M16 — Compliance reports show "None" rows for allowed events
`compliance/report.py:59`
`event.get("stage", "none")` returns `None` (the key exists with value `null` for allowed
calls) → DORA/SOC2 tables contain `| None | N |` rows. Fix: `event.get("stage") or "none"`.

---

## Low

### L1 — Duplicate audit entries after approval
`pipeline/runner.py:71-89` — after PROMPT → approve, the approval decision is logged and the
loop later logs the same request again with `decision=None`.

### L2 — Outbound decisions are not audited
`pipeline/runner.py:92-105` — `scan_outbound` writes nothing to the audit log; secret/PII finds
(CRITICAL severity) are missing from the "tamper-proof audit trail".

### L3 — Injection patterns without word boundaries; flatten-depth evasion
`pipeline/inbound/injection.py:41-42,81` — `ADMIN|ROOT|SUDO` and `override|bypass|skip|disable`
match "administrator", "disabled", "/root/…" at `sensitivity: high` → false-positive flood.
Flattening stops at depth > 5 → evasion vector.

### L4 — CEF injection via unescaped values
`alerts/syslog.py:44-52` — client-controlled `agent_id`, `tool_name`, `reason` are interpolated
unescaped into the CEF string (log injection into the SIEM).

### L5 — Signing key: unencrypted, CWD-relative, permission window, not gitignored
`audit/signer.py:26,42-46`, `.gitignore` — PKCS8 with `NoEncryption()`; path relative to CWD;
`write_bytes` before `chmod(0o600)`; neither `mcp-firewall.key` nor `*.audit.jsonl` is ignored.

### L6 — `_resume_chain` swallows corruption silently
`audit/logger.py:46-47` — broad `except Exception: pass`; a corrupt last line silently restarts
the chain at `"genesis"`.

### L7 — Non-string argument values bypass threat-feed matching
`threatfeed/loader.py:77` — `isinstance(value, str)` guard skips the check; the rule still
matches (fail-open, cf. H6).

### L8 — Fabricated numbers in compliance reports
`compliance/report.py:136,280,306,312-313` — "50+ patterns" (actual: ≤18), "18 patterns"
(actual: 17), "8 security stages" (actual: 6+2), "Timestamp (ISO 8601)" (actual: epoch floats).

### L9 — `AuditData` loads the entire log into RAM; signature check samples 10 events
`compliance/report.py:19,46,131,161`.

### L10 — Alert channels: no connection reuse, blocking syslog in the event loop
`alerts/slack.py:67`, `alerts/webhook.py:26` (new `httpx.AsyncClient` per alert),
`alerts/syslog.py:64` (blocking socket emit in `async def`), `alerts/syslog.py:6` (unused import).

### L11 — Documentation drift
README:36,44,114 (`feed update` doesn't exist, "8+4 checks", OPA/Rego claim),
`docs/policies.md:137` (hot-reload claim — no file watcher exists),
`cli.py:68-82` (`init --enterprise` is a no-op), `docs/use-cases.md` (`alerts:` config doesn't exist).

### L12 — Proxy robustness details
`proxy/stdio.py:61-67` (pending tasks never awaited), `stdio.py:72-74` (`terminate()` without
timeout/kill fallback hangs forever), `stdio.py:172-187` (response sent to notifications with
`"id": null`; denied calls should use a JSON-RPC `error` object).

### L13 — `responseScanning` silently overrides explicit `secrets:`/`pii:` sections
`config.py:59-64` — plus `TypeError` crash on non-dict values (e.g. `secrets: false`).

### L14 — `mcp-firewall audit` reports success for a missing log file
`cli.py:102-118`, `audit/logger.py:91-92` — `verify_chain()` returns `(True, 0, "")` when the
file does not exist.

### L15 — Dashboard server: no error handling, not configurable
`dashboard/server.py:12-18`, `cli.py:51-55` — port 9090 in use → daemon thread dies with a
traceback, proxy continues without dashboard; host/port not configurable in the CLI.

---

## Fix status

All findings were fixed in August 2026 (8 parallel fix groups + wiring + docs pass).
Regression tests live in `tests/test_review_*.py` (173 new tests; suite: 287 passed).

| ID | Severity | Area | Status |
|----|----------|------|--------|
| H1, H2, M14 | high/med | human_approval.py — non-interactive fallback now DENY (configurable), prompt runs via executor, "always" scoped per (agent, tool) | fixed |
| H3, M4, M6 (buffer), M10, L12 | high/med/low | proxy/stdio.py — malformed JSON no longer kills the proxy, DENY wins over REDACT, 10 MB message cap, clean exit 0 on SIGTERM, tasks awaited, terminate timeout + kill fallback, JSON-RPC error objects | fixed |
| H4 | high | proxy derives `agent_id` from the initialize handshake (`clientInfo.name`) | fixed |
| M12 | medium | kill_switch.py — `ValueError` caught, existing SIGUSR1 handler preserved | fixed |
| L1, L2 | low | runner.py — no duplicate audit entries after approval; outbound decisions audited | fixed |
| H6, L7 | high/low | policy.py + threatfeed/loader.py — proper glob escaping (`fnmatch.translate`), invalid patterns fail closed with a warning, non-string values handled | fixed |
| M3 | medium | rate_limiter.py — glob matching (`fetch\|http_*` works), `rule.match.arguments` honored, per-tool windows actually recorded | fixed |
| M6 (maps) | medium | chain_detector.py, rate_limiter.py, dashboard/app.py — bounded maps with eviction/aggregation caps | fixed |
| M1 | medium | egress.py — all dangerous schemes extracted, case-insensitive, bare IPs/hostnames checked (incl. bare dword IPs like `2130706433` when unambiguous, i.e. not a valid port), IPv4 short/octal/hex/dword forms normalized, recursion fixed | fixed |
| M2, L13 | medium/low | config.py — camelCase keys explicitly mapped (`blockPrivateIPs` etc. work now), explicit sections beat `responseScanning`, non-dict values handled | fixed |
| M5 | medium | sdk.py — `ScanResult.blocked` flag; deny returns empty content instead of the secret | fixed |
| L3 | low | injection.py — word boundaries on privilege/override patterns, iterative flattening (depth 20) | fixed |
| H7, H8, M11, L15 (server) | high/med/low | dashboard — broadcast scheduled thread-safe on the uvicorn loop, XSS via `textContent` fixed, replay events no longer double-counted, `limit` validated, port-conflict logged cleanly | fixed |
| M7, M8, L6, L14 (logger) | medium/low | audit/logger.py — hash chain fully under lock, `max_size_mb` rotation with chain-preserving genesis marker, corruption warning, missing file distinguishable | fixed |
| L5 | low | audit/signer.py + .gitignore — key under `$XDG_CONFIG_HOME`, written with 0o600 atomically, key and `*.audit.jsonl` ignored | fixed |
| M16, L8, L9 | medium/low | compliance/report.py — no "None" rows, real pattern counts (dynamic), streaming AuditData, signature check over all events | fixed |
| M15, L4, L10 | medium/low | alerts — `get_running_loop` with sync fallback, task exceptions logged, CEF escaping, shared httpx clients, syslog off the loop; `AlertEngine.close()` added and called from `PipelineRunner.reload_config` so old channels release their HTTP clients | fixed |
| M9, M13, L14 (cli), L15 (cli) | medium/low | cli.py + scanner.py + config.py — `--config` requires existing file, `load_config` raises `FileNotFoundError` for explicit missing paths (SDK fail-closed; `None` keeps default discovery), mcpwn absence detected (exit 3), `shlex.join` quoting, `audit` fails on missing log, `--dashboard-host/--dashboard-port` | fixed |
| L11 (cli) | low | `init --enterprise` generates a real deny-by-default enterprise config | fixed |
| H5 | high | AlertEngine + ThreatFeed wired into the pipeline (both sync and async runner paths); `alerts:`/`threatFeed:` config sections implemented | fixed |
| L11 | low | README, docs/*, ARCHITECTURE.md, CONTRIBUTING.md aligned with reality | fixed |
