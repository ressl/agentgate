"""Keep security unit tests independent of external DNS availability."""

import socket

import pytest


@pytest.fixture(autouse=True)
def public_test_dns(monkeypatch):
    # Literal/private/metadata checks still run normally. DNS behavior tests
    # override this resolver explicitly with private, mixed, or failing answers.
    monkeypatch.setattr(
        "mcp_firewall.pipeline.inbound.egress.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
