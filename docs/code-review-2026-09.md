# Code review — 9 September 2026

Reviewed commit: `44da5cfc65c98ddf3914ff4d95efd5296140bb7c`.

**All 13 confirmed findings are fixed and covered by regression tests.** The original
review found seven P1 and six P2 issues. P1 means a protection
failure or a malformed-message failure that terminates the gateway; P2 means
a narrower correctness, operational, or observability defect. The numbered
descriptions and original line references below describe the reviewed commit,
before fixes.

## Fix verification

| Finding | Implemented behavior | Regression evidence |
| --- | --- | --- |
| 1 | Complete text traversal through content, structured results and extensions; DENY rebuilds a safe result | [Nested output, every copy, combined scanners](../tests/test_september_proxy.py), [shared traversal](../tests/test_september_pipeline.py) |
| 2 | Complete PEM/OpenSSH/PGP blocks removed; truncated blocks consume remaining material | [Generated RSA and partial-block cases](../tests/test_september_pipeline.py) |
| 3 | Agent permissions compose with global restrictions and approval requirements | [Enterprise kube restriction and precedence cases](../tests/test_september_pipeline.py) |
| 4 | Localhost/IPv6/trailing-dot normalization, DNS address checks, fail-closed lookup/depth handling | [Private, mixed DNS, metadata-only and async cases](../tests/test_september_pipeline.py) |
| 5 | Malformed data handled safely; unexpected forwarding/audit failures remain failures | [Wire-data cases and real CLI continuation](../tests/test_september_proxy.py) |
| 6 | Explicit ALLOW continues through chain detection in both runners | [Sync/async composed sequences](../tests/test_september_pipeline.py) |
| 7 | Every present signature verified with a trusted public key; required signatures enforced | [Tampering, public-only verification and CLI cases](../tests/test_september_audit.py) |
| 8 | Audit enablement/path/signing/size reload; signing transitions rotate; invalid reload retains old config | [Audit reload and rollback cases](../tests/test_september_audit.py) |
| 9 | Cross-process lock and incremental chain refresh cover append/rotation; key creation serialized | [Two writers, rotation and four signed subprocess writers](../tests/test_september_audit.py) |
| 10 | Enabled feed loading is strict and atomic, including CLI validation | [Malformed/missing feed and validation cases](../tests/test_september_pipeline.py) |
| 11 | No unconfigured per-agent history; configured unknown-agent limits also enforced | [5,000-call retention and rate-limit cases](../tests/test_september_pipeline.py) |
| 12 | Bounded request correlation, one effective outbound event per response, separate response counters | [Proxy attribution and counting](../tests/test_september_proxy.py), [executed dashboard JavaScript](../tests/test_september_dashboard.py) |
| 13 | Diagnostic EOF is independent of protocol lifetime | [Real server with closed stderr](../tests/test_september_proxy.py) |

Final validation on 9 September 2026:

- **373 tests passed on Python 3.14.7 and 3.11.15**, including 86 additional cases.
- Ruff passes for the application and the five new test/support files; formatting
  checks pass for the same 45 files.
- Strict mypy passes for all 40 application source files.
- Source archive and wheel build successfully. A separate Python 3.11 environment,
  outside the checkout, imports the installed wheel and verifies structured
  redaction, chain enforcement, and all five packaged threat rules.
- `git diff --check` passes. No live deployments or external notifications were made.

Egress remains an argument-inspection control: downstream redirects, DNS changes,
and sockets opened independently by a server require network isolation. Audit
suffix deletion requires a trusted external head checkpoint. These limits and
audit signing-mode migration are documented in [policies](policies.md) and
[audit integrity](compliance.md#audit-trail-integrity).

The review covered the Python application, configuration and example policies,
existing tests, and package build. Each numbered finding was reproduced locally;
the findings are not merely inferred from lint results. No real credentials or
external target systems were used. Synthetic credentials, a disposable in-memory
RSA key, temporary logs, and local mock server subprocesses supplied the evidence.

## P1 findings

### 1. Structured and embedded tool output bypasses response protection

Location: [proxy/stdio.py:296,314–324](../mcp_firewall/proxy/stdio.py),
[outbound/secrets.py:63–66](../mcp_firewall/pipeline/outbound/secrets.py), and
[outbound/pii.py:59–62](../mcp_firewall/pipeline/outbound/pii.py).

Only top-level `content[i].text` is scanned. `structuredContent` is never copied
into the scanning model, and embedded `resource.text` is skipped. The DENY branch
replaces only `result.content`, leaving the original structured result attached.
Both fields are valid MCP tool output, as described in the
[MCP tool-result specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools#tool-result).

**Reproduction:** Return the same synthetic AWS access key in both a text content
block and `structuredContent.key`. With `secrets.action: redact`, the structured
copy survives. With `secrets.action: deny`, it still survives alongside
`isError: true`. A key in an embedded text resource also passes through unchanged.

**Suggested fix:** Scan all supported textual and structured output locations and
apply the decision to every copy. A blocked response must be rebuilt from an
explicit set of safe fields. Add protocol-level coverage for structured output
and embedded resources, including PII and combined REDACT/DENY decisions.

### 2. Private-key redaction removes the header but leaves the key material

Location: [outbound/secrets.py:33–34,73–75](../mcp_firewall/pipeline/outbound/secrets.py).

The private-key patterns match only the `BEGIN … PRIVATE KEY` header. Redaction
replaces that header but returns the complete base64 payload and footer. The SDK
reports the response as modified even though the private key remains recoverable.

**Reproduction:** Generate a disposable RSA key and scan its PKCS8 PEM text using
the default REDACT action. Replace the redaction placeholder with the original
publicly known PEM header and load the returned text using
`load_pem_private_key`. The recovered private numbers equal the original key's.
No private-key bytes were printed or persisted during this check.

**Suggested fix:** Redact the entire PEM block, with explicit handling for partial
or unterminated blocks. Test that returned content cannot reconstruct a key.

### 3. Agent allowlists bypass global credential-file deny rules

Location: [inbound/policy.py:28–32](../mcp_firewall/pipeline/inbound/policy.py).

An agent-specific ALLOW immediately returns from the policy engine, so global
argument restrictions are never evaluated. This contradicts the effective
protection promised by the shipped enterprise example: its allowed reading tools
can read files that the same configuration explicitly denies.

**Reproduction:** Load `examples/policies/enterprise.yaml`, disable only audit
output for the test, and check `read_file` with
`{"path": "/home/alice/.kube/config"}` as `claude-desktop`. The result is ALLOW
despite the `block-kube` rule. The built-in threat feed does not cover this path.

**Suggested fix:** Compose the agent's tool permissions with global argument
restrictions. An agent allowlist should establish eligibility to use a tool,
while global restrictions still constrain its inputs. Define and test precedence
for agent approval requirements as well.

### 4. Private-network checks allow localhost and bare IPv6

Location: [inbound/egress.py:69–85,140–150](../mcp_firewall/pipeline/inbound/egress.py).

`_resolve_ip` parses IP literals; it does not resolve hostnames. `localhost` is
recognized as a host by extraction but then falls through without a deny.
Bare IPv6 addresses such as `::1` do not pass the host extraction heuristic at all.
Hostnames resolving to private addresses likewise receive no address check.

**Reproduction:** With both private-IP and cloud-metadata blocking enabled,
`{"url": "http://localhost:8080/x"}` and `{"host": "::1"}` return no egress
decision. The local resolver confirms that `localhost` resolves to loopback.
`http://127.0.0.1./x` also passes the checker.

**Suggested fix:** Recognize bare IPv6 and normalize local host forms. Clarify that
argument inspection alone cannot enforce the destination actually contacted by
an arbitrary MCP server. Hostname resolution, redirects, and rebinding need
enforcement at the network connection boundary for a reliable SSRF guarantee.

### 5. Malformed server responses terminate the proxy and report success

Location: [proxy/stdio.py:296–300](../mcp_firewall/proxy/stdio.py); shutdown handling
at [proxy/stdio.py:75–99](../mcp_firewall/proxy/stdio.py).

Response-model validation is unguarded, unlike request-model validation. A result
with `content: null`, a string, or `[1]` raises `ValidationError`. A content item
whose `text` is a nonzero number reaches the regex scanner and raises `TypeError`.
The forwarding task dies; `run()` cancels the other tasks and terminates the server.
The resulting SIGTERM is mapped to exit code zero, concealing the proxy failure
from its supervisor. Invalid UTF-8 input also raises an uncaught
`UnicodeDecodeError`, since the JSON handlers only catch `JSONDecodeError`.

**Reproduction:** A local server prints a JSON-RPC result with `content: null` and
then waits. The real CLI proxy exits immediately with status **0**, emits no
response, and logs `Proxy task failed`.

**Suggested fix:** Validate message content at both protocol boundaries and define
a controlled response or disconnect for malformed data. Preserve a nonzero proxy
exit status when a forwarding task fails. Add subprocess-level failure tests.

### 6. Explicit ALLOW decisions disable chain detection

Location: [pipeline/runner.py:145–149,193–197](../mcp_firewall/pipeline/runner.py).

Both runner variants return immediately on ALLOW. Because the chain detector runs
after policy, explicitly allowed calls are neither recorded nor checked for
dangerous sequences. Adding an allowlist therefore disables a security stage that
works with `defaultAction: allow` alone. The generated starter policy explicitly
allows the read tools that should supply history for chain detection.

**Reproduction:** Under default ALLOW, `read_file` followed by `http_post` to a
public example URL is denied by `chain_detector`. Add an explicit ALLOW rule for
`read_file|http_post`, repeat the same sequence in a fresh gateway, and both calls
are allowed.

**Suggested fix:** Treat policy ALLOW as successful completion of the policy
stage, then continue mandatory security stages. Record relevant allowed calls
consistently in both sync and async execution paths.

### 7. Audit integrity verification ignores Ed25519 signatures

Location: [audit/logger.py:166–181](../mcp_firewall/audit/logger.py).

`verify_chain()` checks only `previous_hash`; it never invokes signature
verification. The final entry has no subsequent entry protecting its content,
so changing it is accepted even with signing enabled. More generally, a writer
can alter entries and recompute the hash links without possessing the signing
key. The CLI uses this function to report that integrity is verified.

**Reproduction:** Create a temporary signed two-entry log, change only the final
entry's `tool_name`, and leave its signature untouched. `verify_chain()` returns
`True`, while explicitly verifying that same entry using the signer returns
`False`.

**Suggested fix:** Verify every signature against a trusted public key and enforce
whether signatures are required. Expose verification without loading or creating
a private key. Detecting removal of a valid log suffix additionally requires a
trusted external record of the expected chain head.

## P2 findings

### 8. Audit configuration changes do not apply on SDK reload

Location: [pipeline/runner.py:224–231](../mcp_firewall/pipeline/runner.py).

Reload changes `self.config`, alerts, and threat rules, but leaves the existing
`AuditLogger` untouched. That object captured `enabled`, path, signer, and size
limit during construction, so its behavior disagrees with the new configuration.

**Reproduction:** Start a runner with auditing disabled, reload with auditing and
signing enabled at a new temporary path, then evaluate a call. Configuration says
enabled, the logger still says disabled, and no log file is created.

**Suggested fix:** Apply audit changes safely during reload, with explicit chain
handling for path/signing changes. Verify enabled/disabled transitions as well as
rotation settings.

### 9. Separate audit writers corrupt a shared log's chain

Location: [audit/logger.py:19–26,65–97](../mcp_firewall/audit/logger.py).

The lock and cached chain head belong to one `AuditLogger` instance. Two gateways
using the same configured/default path therefore serialize neither the head read
nor the append against one another. Thread safety of an individual logger does
not cover multiple instances or processes.

**Reproduction:** Construct two loggers for the same previously absent temporary
path. Append once through each, even sequentially. Both use `genesis`, and chain
verification fails at the second entry.

**Suggested fix:** Enforce single-writer ownership, provide separate log paths per
proxy, or use interprocess locking that covers refreshing the actual chain head,
rotation, signing, and append.

### 10. Invalid custom threat rules are silently omitted

Location: [threatfeed/loader.py:139–151](../mcp_firewall/threatfeed/loader.py).

Directory loading suppresses every exception and also silently accepts a missing
directory. A mistake in a configured deny rule can remove the intended protection
without failing startup or even naming the failed file in a warning.

**Reproduction:** Configure a custom directory containing a deny rule for
`**/private.txt` with the typo `severity: higgh`. Pipeline construction succeeds,
only the five built-in rules load, and `/data/private.txt` is allowed under default
ALLOW.

**Suggested fix:** Validate every configured rule and report file-specific errors.
Reject invalid explicitly configured protection unless the operator deliberately
selects a documented permissive loading mode. Make `validate` exercise feed loading.

### 11. Per-agent rate history grows indefinitely without a per-agent limit

Location: [inbound/rate_limiter.py:80–86,114–117](../mcp_firewall/pipeline/inbound/rate_limiter.py).

Every named agent gets a timestamp appended on every admitted call, but that
agent's timestamps are pruned only when its per-agent limit is checked or the map
hits the distinct-key eviction threshold. A normal long-lived named client with
only the default global limit accumulates its entire call history. Bounding the
number of keys does not bound these timestamp lists.

**Reproduction:** Simulate 5,000 calls from one named agent, spaced 61 seconds
apart. The global window retains one timestamp; the agent window retains all
5,000, spanning roughly 85 hours.

**Suggested fix:** Retain only history required by configured windows, prune on
append, and use a bounded time-aware data structure. Account for configuration
reload semantics when choosing retention.

### 12. Response redactions and denials never reach the dashboard

Location: [proxy/stdio.py:310–324](../mcp_firewall/proxy/stdio.py).

Inbound decisions call `dashboard_state.add_event`; outbound decisions only write
to the console and audit pipeline. Consequently the dashboard's redaction counter
stays at zero and its feed reports the inbound allow without showing subsequent
response blocking or redaction.

**Reproduction:** Pass an allowed tool request followed by a response containing a
synthetic secret through the proxy interceptors. The secret is redacted, but the
dashboard receives zero new events and zero new redactions for the scan.

**Suggested fix:** Publish outbound decisions and distinguish response findings
from tool-call totals. Track pending request IDs so dashboard events and outbound
audit/alert records retain the original tool and agent identity.

### 13. Closing server stderr shuts down a healthy proxy session

Location: [proxy/stdio.py:70–73](../mcp_firewall/proxy/stdio.py).

The diagnostic stderr forwarding task participates in `FIRST_COMPLETED` alongside
the protocol streams. A server that closes stderr while continuing to serve
stdin/stdout causes the proxy to cancel both protocol directions and terminate it.

**Reproduction:** A local server closes file descriptor 2, waits 0.2 seconds, and
then attempts to emit a valid JSON-RPC response. The proxy exits with status 0
before the response is sent; stdout is empty and no task failure is reported.

**Suggested fix:** Manage diagnostic stream completion independently of protocol
and process lifetime. Add an integration test for a live server with closed stderr.

## Further observations from the original review

Integration coverage, lint/type checks, PyYAML stubs, and the obsolete audit command
examples were addressed with the fixes. Broader items below, such as authenticated
client identity, SDK defaults, alert lifecycle and compliance aggregation, are
separate from the 13 numbered findings.

- Add tests that compose security stages and use real proxy subprocesses. Existing
  tests cover many individual cases but miss the policy interaction and protocol
  boundary failures above. Keep sync and async decisions consistent through a
  shared decision-processing implementation.
- Make configuration schemas strict and action-specific. Unknown fields are
  generally discarded; malformed rate-limit strings disable the relevant limit;
  the shared action enum accepts values some stages do not handle. Reject invalid
  protection settings during validation.
- Define SDK security defaults explicitly. `Gateway` defaults to auto-approval,
  and loading a config file disables auditing even if that file enables it
  (`sdk.py:91,98–100`). Treat these as deliberate opt-ins or make the differences
  from proxy mode clear to callers. Client-provided `clientInfo.name` is likewise
  a label, not an authenticated identity; stronger RBAC needs an operator-bound
  identity or other trust mechanism.
- Give alerts an awaited shutdown lifecycle and bounded delivery queue. Current
  send tasks are fire-and-forget, and the gateway/proxy has no normal close path
  that drains them and closes shared HTTP clients.
- Align reporting with actual evidence: outbound findings add audit entries, so
  entry counts are not necessarily tool-call counts. The supposedly bounded
  `AuditData.critical_events` list has no cap. Documentation still uses
  `mcp-firewall audit verify`, while the implemented command is `mcp-firewall audit`.
- Establish a passing lint/type baseline and automate it. Prioritize actual
  typing and exception-handling issues before formatting. Add `types-PyYAML` to
  development dependencies and modernize the deprecated license table.

## Original validation before fixes

| Check | Result |
| --- | --- |
| `.venv/bin/python -m pytest -q` | **287 passed** in 1.39 s |
| Focused reproductions | All 13 numbered findings reproduced |
| Real CLI subprocess checks | Malformed response and closed stderr both terminate with status 0 |
| `uvx ruff check mcp_firewall --statistics` | **84 findings**, Ruff 0.16.6 |
| `uvx mypy --python-executable .venv/bin/python mcp_firewall` | **31 errors in 11 files**, mypy 2.3.1; includes missing PyYAML stubs |
| `uv build --out-dir /tmp/mcp-firewall-review-dist` | Source archive and wheel built successfully |
| Wheel inspection | All five built-in YAML threat rules included |

Runtime validation used Python 3.14.7 on macOS. Other advertised Python versions
were not exercised. The initially installed virtual environment lacked Ruff and
mypy, so those checks used isolated `uvx` tools. Packaging succeeds but emits a
setuptools warning about deprecated `project.license` table syntax. This was a
local code review, not a live deployment assessment or an exhaustive proof of
security. Those checks preceded the application fixes verified above.
