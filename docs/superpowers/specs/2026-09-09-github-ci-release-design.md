# GitHub CI and first prerelease

The approved next milestone is automated GitHub checks, a substantive reply to
issue #2, and a published version with experimental recovery clearly identified.

## Scope and decisions

Use the repository's existing public GitHub origin. CI is self-contained and has
no private infrastructure, deployment credentials or external-service dependency
other than public package registries and the pinned public AgentReins source.

Add pull-request checks targeting main, main/tag push checks and manual dispatch:
- Ruff/format across the repository and strict mypy for the firewall modules.
- Full Python tests on 3.11, 3.12, 3.13 and 3.14 on Ubuntu 24.04.
- macOS 15 with Xcode 26.3: Python tests plus fresh pinned AgentReins install,
  compilation, existing Swift tests and real controller/proxy integration tests.
- Build source/wheel archives and install each in a fresh environment, running
  version, packaged-resource and private snapshot API smoke checks.
- An aggregate status fails if any required job fails, is skipped or is cancelled.

Pin GitHub Actions by commit and direct quality/build tools by version. Use
read-only repository tokens, disabled persisted checkout credentials, ordinary
pull_request events, timeouts and branch concurrency cancellation. Upload only
package artifacts/checksums/build identity; no credentials or application history.
Correct existing test lint/format findings rather than exempting old test files.

Publish the first GitHub prerelease as v0.2.0a1 after the exact tag's CI succeeds.
Set matching Python metadata/runtime versions, provide CHANGELOG/release notes,
and attach the archives produced by that verified tag run with checksums and
build identity. No PyPI upload, notarized app, production deployment or upstream
AgentReins publication is included. A prerelease is appropriate because native
compatibility is pinned and file recovery remains experimental and process-local.

Alternatives considered: stable 0.2.0 would overstate maturity; CI plus a draft-only
release would leave the approved publication unfinished. A checked GitHub
prerelease delivers a usable artifact with explicit limits.

Reply to issue #2 with the published version, implemented IPC/approval adapter,
reproducible demo, strict evidence and rollback boundaries, and a concrete question
about upstream integration. Keep the collaboration issue open for the author.
The user approved answering this named issue; no additional channels are used.

## Plan and acceptance

1. Commit this design; fix lint baseline and add CI/tool pins/package smoke scripts.
2. Add version/changelog/release instructions and review the exact issue reply.
3. Validate locally; push a PR and fix actual GitHub failures until all jobs pass.
4. Merge, verify main, tag the tested release commit, verify tag CI and publish its
   exact package artifacts. Confirm remote version/assets and download checksums.
5. Post and verify the issue reply; record durable results in Agent Brain.

The previously approved milestone covers these implementation choices. The
writing-plans skill is absent from the shared and Codex skill roots; the ordered
plan above is the local fallback. Reviewed for scope, consistent release identity,
credential boundaries and failure handling.
