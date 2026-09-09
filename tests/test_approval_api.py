"""Security boundary for the local approval controller."""

import asyncio

import httpx
import pytest
from click.testing import CliRunner

from mcp_firewall.approvals import ApprovalBroker
from mcp_firewall.cli import main
from mcp_firewall.dashboard.app import app
from mcp_firewall.dashboard.approvals import configure_approvals
from mcp_firewall.models import ToolCallRequest

TOKEN = "test-controller-token-" * 3
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
async def controller():
    broker = ApprovalBroker()
    configure_approvals(broker, TOKEN)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:9090"
    ) as client:
        yield broker, client
    broker.close()
    configure_approvals(None, None)


async def test_authentication_origin_and_host_checks(controller):
    broker, client = controller
    for headers, status in [
        ({}, 401),
        ({"Authorization": "Bearer incorrect"}, 401),
        ({**AUTH, "Origin": "https://attacker.example"}, 403),
        ({**AUTH, "Origin": "null"}, 403),
        ({**AUTH, "Host": "attacker.example"}, 403),
        ({**AUTH, "Sec-Fetch-Site": "cross-site"}, 403),
    ]:
        response = await client.get("/api/approvals", headers=headers)
        assert response.status_code == status
        assert response.headers["cache-control"] == "no-store"
    assert not (await broker.arequest(ToolCallRequest(tool_name="status"), "s")).approved
    response = await client.get(
        "/api/approvals", headers={**AUTH, "Origin": "http://127.0.0.1:9090"}
    )
    assert response.status_code == 200


async def test_authenticated_single_call_flow_and_strict_decisions(controller):
    broker, client = controller
    await client.get("/api/approvals", headers=AUTH)
    task = asyncio.create_task(
        broker.arequest(
            ToolCallRequest(tool_name="status", arguments={"password": "hidden-value"}), "s"
        )
    )
    await asyncio.sleep(0.01)
    response = await client.get("/api/approvals", headers=AUTH)
    item = response.json()[0]
    assert "hidden-value" not in response.text
    assert "arguments_preview" not in (await client.get("/api/events")).text
    path = f"/api/approvals/{item['id']}"
    for body in [
        {"request_hash": item["request_hash"], "allow": "false"},
        {"request_hash": item["request_hash"], "allow": True, "extra": "hidden-value"},
        {"request_hash": "x" * 64, "allow": True},
    ]:
        bad = await client.post(path, headers=AUTH, json=body)
        assert bad.status_code == 400
        assert "hidden-value" not in bad.text
    tampered = await client.post(
        path,
        headers=AUTH,
        json={
            "request_hash": "0" * 64,
            "allow": True,
        },
    )
    assert tampered.status_code == 409
    approved = await client.post(
        path,
        headers=AUTH,
        json={
            "request_hash": item["request_hash"],
            "allow": True,
        },
    )
    assert approved.status_code == 200
    assert approved.headers["cache-control"] == "no-store"
    assert (await task).approved
    assert (
        await client.post(
            path,
            headers=AUTH,
            json={
                "request_hash": item["request_hash"],
                "allow": True,
            },
        )
    ).status_code == 409


async def test_disconnect_and_bounded_body(controller):
    broker, client = controller
    await client.get("/api/approvals", headers=AUTH)
    task = asyncio.create_task(broker.arequest(ToolCallRequest(tool_name="status"), "s"))
    await asyncio.sleep(0.01)
    response = await client.post(
        "/api/approvals/unknown",
        headers={
            **AUTH,
            "Content-Type": "application/json",
        },
        content=b"x" * 2048,
    )
    assert response.status_code == 413
    assert (await client.post("/api/approvals/disconnect", headers=AUTH)).status_code == 200
    assert not (await task).approved


async def test_page_cannot_be_framed_and_disabled_api_is_unavailable(controller):
    _, client = controller
    page = await client.get("/")
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert TOKEN not in page.text
    configure_approvals(None, None)
    assert (await client.get("/api/approvals", headers=AUTH)).status_code == 404
    assert (await client.get("/api/approval-mode")).json() == {"enabled": False}


def test_cli_requires_token_and_loopback_before_starting_proxy(monkeypatch):
    runner = CliRunner()
    monkeypatch.delenv("MCP_FIREWALL_DASHBOARD_TOKEN", raising=False)
    result = runner.invoke(main, ["wrap", "--dashboard-approvals", "--", "unused"])
    assert result.exit_code != 0
    assert "MCP_FIREWALL_DASHBOARD_TOKEN" in result.output
    monkeypatch.setenv("MCP_FIREWALL_DASHBOARD_TOKEN", TOKEN)
    result = runner.invoke(
        main,
        [
            "wrap",
            "--dashboard-approvals",
            "--dashboard-host",
            "0.0.0.0",  # noqa: S104 — verify unsafe bind is rejected
            "--",
            "unused",
        ],
    )
    assert result.exit_code != 0
    assert "loopback" in result.output
    assert TOKEN not in result.output
