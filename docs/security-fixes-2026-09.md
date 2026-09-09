# September review implementation

Scope: all 13 numbered findings in `code-review-2026-09.md`. The requested fixes
follow that review's proposed behavior.

1. Scan all text in tool result content, structured results, and extra result
   fields through a shared traversal. Replace blocked results with a safe result.
   Remove complete private-key blocks, including truncated blocks.
2. Compose agent permissions with first-match global rules; global denial wins,
   approval requirements survive global allows. Continue chain checks after ALLOW.
3. Normalize IPv4/IPv6 and localhost names; check hostname resolution before
   admission. Document that downstream DNS changes and redirects require network
   enforcement outside the stdio proxy.
4. Validate both protocol directions. Reject malformed messages without losing
   a healthy session; unexpected forwarding failures must exit nonzero. Treat
   stderr as diagnostic output, independent of protocol lifetime.
5. Verify signatures using trusted public keys without requiring private-key
   access. Coordinate audit writers with a separate cross-process lock file and
   refresh their chain state before appending. Apply audit reloads atomically;
   changing signing mode starts an archived, linked new generation.
6. Load enabled threat feeds strictly and atomically; invalid files or directories
   fail validation/startup/reload. Do not retain unconfigured agent rate histories.
7. Correlate requests and responses using a bounded pending map; publish outbound
   dashboard events without counting them as additional tool calls.

Validation: regressions for every finding, adversarial protocol and response cases,
real subprocess lifecycle and concurrent audit writer tests, existing suite,
lint/type checks on changed code, wheel/source build and packaged rule inspection.

Completed and verified on 9 September 2026. All 13 requirements are
implemented and mapped to regression coverage in the review's fix-verification
table. Final results: 373 tests pass on Python 3.11 and 3.14; application Ruff,
formatting, and strict mypy checks pass. The built wheel passes an isolated install
smoke test. This source change does not include a package release or deployment.
