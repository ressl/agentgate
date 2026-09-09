"""Validate distribution identity/contents and write a public release manifest."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path


def check(directory: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    sha = os.environ["SOURCE_SHA"]
    ref = os.environ["SOURCE_REF"]
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("Expected a full source commit")
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{version}":
        raise ValueError("Release tag does not match package version")
    wheels = list(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("Expected exactly one wheel and one source archive")
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        if metadata["Name"] != "mcp-firewall" or metadata["Version"] != version:
            raise ValueError("Wheel metadata mismatch")
        for required in (
            "mcp_firewall/workspace/files.py",
            "mcp_firewall/dashboard/workspace.py",
            "mcp_firewall/threatfeed/rules/cloud-metadata.yaml",
        ):
            if required not in names:
                raise ValueError(f"Missing wheel resource: {required}")
        if any(name.startswith("integrations/") for name in names):
            raise ValueError("Native development sources unexpectedly shipped in the wheel")
    with tarfile.open(sources[0]) as source:
        names = source.getnames()
        for suffix in (
            "/integrations/agentreins/Sources/MCPFirewallWorkspaceView.swift",
            "/integrations/agentreins/demo.py",
            "/integrations/agentreins/install.py",
            "/integrations/agentreins/verify.py",
            "/docs/workspace-rollback.md",
            "/ci/smoke_installed.py",
        ):
            if not any(name.endswith(suffix) for name in names):
                raise ValueError(f"Missing source resource: {suffix}")
    archives = sorted(wheels + sources)
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in archives}
    identity = directory / "BUILD-INFO.json"
    identity.write_text(
        json.dumps(
            {
                "version": version,
                "source_sha": sha,
                "source_ref": ref,
                "run_id": os.environ["CI_RUN_ID"],
                "archives": hashes,
            },
            indent=2,
        )
        + "\n"
    )
    hashes[identity.name] = hashlib.sha256(identity.read_bytes()).hexdigest()
    (directory / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in hashes.items())
    )
    print(f"Validated {version} archives for {sha}; wrote checksums and build identity")


if __name__ == "__main__":
    check(Path(sys.argv[1]))
