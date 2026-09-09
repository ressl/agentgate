# GitHub releases

The repository publishes Python archives as GitHub prereleases while the native
adapter and workspace recovery are experimental. It does not automatically
publish to PyPI, sign/notarize AgentReins, or deploy any service.

## Validation and identity

The [CI workflow](../.github/workflows/ci.yml) runs on pull requests targeting
`main`, pushes to `main`, `v*` tags, and manual dispatch. `Required checks` succeeds
only if quality, all Python matrix entries, native integration, and packaging
succeed. This status can be selected in branch protection; the workflow itself
does not change repository settings.

Linux tests cover Python 3.11, 3.12, 3.13 and 3.14. macOS 15 uses Xcode 26.3 and
Python 3.11, fetches the pinned public AgentReins commit, installs the adapter,
runs upstream/adapter Swift tests, and exercises the real controller/proxy using
`verify.py`. These are controller/model integration tests; GUI click automation
and code signing are not included. Upstream availability is required.

Actions use full commit pins, read-only repository permissions and no stored
checkout credentials. CI needs no private credentials. Direct CI tools are in
`requirements/ci.txt`; application dependencies and build-backend dependencies
are resolved from public registries, so builds are not fully hermetic.

The `python-distributions` artifact contains one wheel, one source archive,
`BUILD-INFO.json` and `SHA256SUMS`. Packaging validates the version and resources,
then installs each archive into a fresh environment outside the checkout and
checks the CLI, packaged rules, authenticated file diff/restore, replay rejection,
and approval lease isolation. Build identity includes source SHA, ref, run ID and
archive digests. These checksums detect accidental corruption; they are not a
cryptographic publisher signature or independent provenance attestation.

## Maintainer procedure

1. Update `pyproject.toml`, `mcp_firewall/__init__.py` and `CHANGELOG.md` together.
   Review compatibility and experimental limits. Open a PR and wait for all CI
   jobs to pass before merging.
2. Verify the merged commit's CI. Create `v<version>` at that exact commit and push
   that tag. CI rejects a tag that differs from the package version.
3. Wait for the tag's own CI run to succeed, then download its
   `python-distributions` artifact with `gh run download`. Do not reuse PR or local
   build outputs. Match `BUILD-INFO.json` to the exact tag commit, ref, version and
   run ID; verify every file with `shasum -a 256 -c SHA256SUMS`.
4. Publish using `gh release create <tag> --verify-tag --prerelease --latest=false
   --notes-file <notes>` and attach the wheel, source, build identity and checksums.
   Include installation instructions and the current experimental limits.
5. Download the published assets again and verify identity/checksums. Keep release
   tags immutable; corrections receive a new version and a new CI run.

To try a prerelease, download the wheel and checksums from the corresponding
[GitHub release](https://github.com/ressl/mcp-firewall/releases), verify checksums,
and install that wheel in a fresh Python 3.11+ environment. The source archive
also contains the native adapter and demo; the Python wheel contains the firewall.
