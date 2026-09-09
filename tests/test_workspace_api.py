"""Workspace recovery is private, bounded and revision-bound."""

import uuid

import httpx
import pytest
from click.testing import CliRunner

from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.cli import main
from mcp_firewall.dashboard.app import app
from mcp_firewall.dashboard.approvals import configure_approvals
from mcp_firewall.dashboard.workspace import configure_workspace
from mcp_firewall.workspace import WorkspaceSnapshots

TOKEN = "synthetic-workspace-controller-token-only"


@pytest.fixture
async def controller(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    manager = WorkspaceSnapshots(root)
    broker = ApprovalBroker()
    configure_approvals(broker, TOKEN)
    configure_workspace(manager)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
    ) as client:
        try:
            yield client, root, manager, broker
        finally:
            configure_workspace(None)
            configure_approvals(None, None)
            broker.close()


def auth(**extra):
    return {"Authorization": f"Bearer {TOKEN}", **extra}


def capture(root, manager):
    target = root / "private.txt"
    target.write_text("private-before")
    call = str(uuid.uuid4())
    manager.begin(str(uuid.uuid4()), call, "edit")
    target.write_text("private-after")
    manager.finish(call)
    return manager.view().snapshots[0]


async def test_authentication_no_store_and_private_payload(controller):
    client, root, manager, broker = controller
    item = capture(root, manager)
    file = item.files[0]
    base = f"/api/workspace/{item.id}"
    paths = ["/api/workspace", base, f"{base}/files/{file.id}"]
    for path in paths:
        for headers, status in [({}, 401), (auth(Origin="https://foreign.test"), 403)]:
            response = await client.get(path, headers=headers)
            assert response.status_code == status
            assert response.headers["cache-control"] == "no-store"
            assert "private" not in response.text
    for path in [f"{base}/discard", f"{base}/files/{file.id}/restore"]:
        assert (await client.post(path, json={"revision": item.revision})).status_code == 401
    listing = await client.get("/api/workspace", headers=auth())
    assert listing.json()["snapshots"][0]["files"] == []
    assert listing.json()["snapshots"][0]["file_count"] == 1
    assert "private.txt" not in listing.text
    assert "private-before" not in listing.text
    assert "private-after" not in listing.text
    detail = await client.get(base, headers=auth())
    assert detail.json()["files"][0]["path"] == "private.txt"
    assert "private-before" not in detail.text
    preview = await client.get(f"{base}/files/{file.id}", headers=auth())
    assert "private-before" in preview.json()["diff"]
    assert preview.headers["cache-control"] == "no-store"
    assert broker._controller_seen is None
    events = await client.get("/api/integration-events", headers=auth())
    assert "private" not in events.text


async def test_exact_revision_restore_conflict_replay_and_discard(controller):
    client, root, manager, _ = controller
    item = capture(root, manager)
    path = f"/api/workspace/{item.id}/files/{item.files[0].id}/restore"
    wrong = await client.post(path, headers=auth(), json={"revision": str(uuid.uuid4())})
    assert wrong.status_code == 409
    assert (root / "private.txt").read_text() == "private-after"
    restored = await client.post(path, headers=auth(), json={"revision": item.revision})
    assert restored.status_code == 200
    assert restored.json()["files"][0]["restored"]
    assert (root / "private.txt").read_text() == "private-before"
    assert (
        await client.post(path, headers=auth(), json={"revision": item.revision})
    ).status_code == 409
    discarded = await client.post(
        f"/api/workspace/{item.id}/discard",
        headers=auth(),
        json={"revision": restored.json()["revision"]},
    )
    assert discarded.json() == {"discarded": True}
    assert manager.view().snapshots == []


async def test_payload_limits_and_disabled_mode(controller):
    client, _, _, _ = controller
    path = f"/api/workspace/{uuid.uuid4()}/discard"
    assert (await client.post(path, headers=auth(), content="{}")).status_code == 415
    response = await client.post(path, headers=auth(), json={"revision": "private" * 100})
    assert response.status_code == 413 and "private" not in response.text
    response = await client.post(path, headers=auth(), json={"revision": "private"})
    assert response.status_code == 400 and "private" not in response.text
    configure_workspace(None)
    assert (await client.get("/api/workspace", headers=auth())).json()["enabled"] is False
    assert (await client.post(path, headers=auth(), json={})).status_code == 404


def test_cli_requires_explicit_authenticated_snapshot_mode(tmp_path):
    result = CliRunner().invoke(
        main, ["wrap", "--snapshot-workspace", str(tmp_path), "--", "unused"]
    )
    assert result.exit_code != 0
    assert "requires --dashboard-approvals" in result.output
