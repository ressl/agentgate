"""Exercise an installed distribution without importing the source checkout."""

from __future__ import annotations

import asyncio
import secrets
import sys
import tempfile
import uuid
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

import httpx

import mcp_firewall
from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.dashboard.app import app
from mcp_firewall.dashboard.approvals import configure_approvals
from mcp_firewall.dashboard.workspace import configure_workspace
from mcp_firewall.workspace import WorkspaceSnapshots


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


async def run(expected_version: str, source_root: Path) -> None:
    module_path = Path(mcp_firewall.__file__).resolve()
    require(not module_path.is_relative_to(source_root.resolve()), "Imported the source checkout")
    require(version("mcp-firewall") == expected_version, "Distribution version mismatch")
    require(mcp_firewall.__version__ == expected_version, "Runtime version mismatch")
    require(
        files("mcp_firewall").joinpath("threatfeed/rules/cloud-metadata.yaml").is_file(),
        "Packaged threat feed is missing",
    )
    broker = ApprovalBroker()
    credential = secrets.token_urlsafe(32)
    configure_approvals(broker, credential)
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "file"
            target.write_text("original\n")
            snapshots = WorkspaceSnapshots(root)
            configure_workspace(snapshots)
            call = str(uuid.uuid4())
            snapshots.begin(str(uuid.uuid4()), call, "edit")
            target.write_text("tool\n")
            snapshots.finish(call)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
            ) as client:
                require(
                    (await client.get("/api/workspace")).status_code == 401, "Missing auth gate"
                )
                client.headers["Authorization"] = "Bearer " + credential
                listing = await client.get("/api/workspace")
                require(
                    listing.headers["cache-control"] == "no-store", "Private response is cached"
                )
                summary = listing.json()["snapshots"][0]
                require(
                    summary["files"] == [] and summary["file_count"] == 1, "Wrong public summary"
                )
                detail = (await client.get("/api/workspace/" + summary["id"])).json()
                route = "/api/workspace/" + detail["id"] + "/files/" + detail["files"][0]["id"]
                preview = (await client.get(route)).json()
                require(
                    "-original" in preview["diff"] and "+tool" in preview["diff"], "Wrong file diff"
                )
                body = {"revision": preview["revision"]}
                response = await client.post(route + "/restore", json=body)
                require(response.status_code == 200, "Restore failed")
                require(
                    target.read_text() == "original\n", "Restore did not recover original bytes"
                )
                require(
                    (await client.post(route + "/restore", json=body)).status_code == 409,
                    "Consumed restore was replayable",
                )
                require(broker._controller_seen is None, "File reads renewed the approval lease")
    finally:
        configure_workspace(None)
        configure_approvals(None, None)
        broker.close()
    print(f"PASS: installed {expected_version}: resources, auth, diff, restore, replay and lease")


if __name__ == "__main__":
    asyncio.run(run(sys.argv[1], Path(sys.argv[2])))
