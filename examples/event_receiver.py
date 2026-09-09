"""Loopback-only event receiver example with authentication and bounded deduplication.

Set MCP_FIREWALL_RECEIVER_TOKEN, then run this file from an installed environment.
This example observes events; it never approves calls or changes workspace files.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections import OrderedDict

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from mcp_firewall.models import EventEnvelope

logger = logging.getLogger("event_receiver")
MAX_BODY_BYTES = 64 * 1024
MAX_SEEN_EVENTS = 10000


def create_app(token: str) -> FastAPI:
    if len(token) < 32:
        raise ValueError("Use a receiver token of at least 32 characters")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    seen: OrderedDict[str, None] = OrderedDict()
    expected = ("Bearer " + token).encode()

    @app.post("/events")
    async def receive(request: Request) -> dict[str, str | bool]:
        supplied = request.headers.get("authorization", "").encode()
        if not hmac.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="Unauthorized")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Event exceeds size limit")
            body.extend(chunk)
        try:
            envelope = EventEnvelope.model_validate_json(body)
        except ValidationError:
            # Never echo submitted content or validation input back to the sender.
            raise HTTPException(status_code=400, detail="Invalid event envelope") from None
        event = envelope.event
        if request.headers.get("idempotency-key") != event.id:
            raise HTTPException(status_code=400, detail="Event ID does not match delivery key")
        duplicate = event.id in seen
        if not duplicate:
            seen[event.id] = None
            if len(seen) > MAX_SEEN_EVENTS:
                seen.popitem(last=False)
            # IDs are validated UUIDs. Do not print arbitrary tool output or labels.
            logger.info(
                "Observed %s for call %s (event %s)", event.phase.value, event.call_id, event.id
            )
        return {"accepted": True, "duplicate": duplicate, "event_id": event.id}

    return app


def main() -> None:
    token = os.environ.get("MCP_FIREWALL_RECEIVER_TOKEN", "")
    if len(token) < 32:
        raise SystemExit(
            "Set MCP_FIREWALL_RECEIVER_TOKEN to a random value of at least 32 characters"
        )
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(token), host="127.0.0.1", port=8766, access_log=False)


if __name__ == "__main__":
    main()
