"""Authenticated local controller API, separate from public dashboard events."""

from __future__ import annotations

import hashlib
import hmac

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError

from ..approvals import ApprovalBroker, PendingApproval
from .event_feed import IntegrationEventPage, event_feed

router = APIRouter()
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
_broker: ApprovalBroker | None = None
_token_digest: bytes | None = None
_NO_STORE = {"Cache-Control": "no-store"}


def configure_approvals(broker: ApprovalBroker | None, token: str | None) -> None:
    """Configure the process's local controller before starting its HTTP server."""
    global _broker, _token_digest
    if broker is not None and (
        token is None
        or not 32 <= len(token) <= 1024
        or not token.isascii()
        or not token.isprintable()
        or any(character.isspace() for character in token)
    ):
        raise ValueError("MCP_FIREWALL_DASHBOARD_TOKEN must contain 32–1024 ASCII characters")
    if _broker is not None and _broker is not broker:
        _broker.disconnect()
    _token_digest = hashlib.sha256(token.encode()).digest() if token and broker else None
    _broker = broker
    event_feed.reset(enabled=broker is not None)


def _error(status: int, detail: str) -> HTTPException:
    return HTTPException(status_code=status, detail=detail, headers=_NO_STORE)


def _authenticate(request: Request) -> ApprovalBroker:
    if _broker is None or _token_digest is None:
        raise _error(404, "Approval controller is disabled")
    authorization = request.headers.get("authorization", "")
    if len(authorization) > 1031 or not authorization.startswith("Bearer "):
        raise _error(401, "Approval authentication required")
    digest = hashlib.sha256(authorization[7:].encode()).digest()
    if not hmac.compare_digest(digest, _token_digest):
        raise _error(401, "Approval authentication required")
    origin = request.headers.get("origin")
    expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if (
        request.url.hostname not in LOOPBACK_HOSTS
        or (origin is not None and origin != expected_origin)
        or request.headers.get("sec-fetch-site") == "cross-site"
    ):
        raise _error(403, "Approval controller requires a local, same-origin request")
    return _broker


class _Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    allow: StrictBool


@router.get("/api/approval-mode")
async def approval_mode() -> dict[str, bool]:
    return {"enabled": _broker is not None}


@router.get("/api/integration-events")
async def integration_events(
    request: Request,
    after: int = Query(0, ge=0, le=2**53 - 1),
    stream_id: str | None = Query(None, max_length=36),
    limit: int = Query(256, ge=1, le=256),
) -> IntegrationEventPage:
    _authenticate(request)  # Reading evidence does not renew the approval lease.
    try:
        return event_feed.read(after=after, stream_id=stream_id, limit=limit)
    except LookupError:
        raise _error(409, "Event stream restarted; reconnect explicitly") from None
    except ValueError:
        raise _error(400, "Invalid event cursor") from None


@router.get("/api/approvals")
async def pending_approvals(request: Request) -> list[PendingApproval]:
    return _authenticate(request).pending()


@router.post("/api/approvals/disconnect")
async def disconnect(request: Request) -> dict[str, bool]:
    _authenticate(request).disconnect()
    return {"connected": False}


@router.post("/api/approvals/{approval_id}")
async def decide(approval_id: str, request: Request) -> dict[str, bool]:
    broker = _authenticate(request)
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise _error(415, "Approval decision requires application/json")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 1024:
            raise _error(413, "Approval decision is too large")
        body.extend(chunk)
    try:
        decision = _Decision.model_validate_json(bytes(body))
    except ValidationError:
        # Default validation responses echo input; never reflect arbitrary input here.
        raise _error(400, "Invalid approval decision") from None
    try:
        broker.decide(approval_id, decision.request_hash, decision.allow)
    except (LookupError, ValueError):
        raise _error(409, "Approval expired, changed, or binding does not match") from None
    return {"accepted": True}
