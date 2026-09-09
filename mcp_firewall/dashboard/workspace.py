"""Private snapshot review and single-file recovery routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from ..workspace import FilePreview, SnapshotView, WorkspaceSnapshots, WorkspaceView
from ..workspace.files import WorkspaceError
from .approvals import _authenticate, _error

router = APIRouter()
_snapshots: WorkspaceSnapshots | None = None


def configure_workspace(snapshots: WorkspaceSnapshots | None) -> None:
    global _snapshots
    _snapshots = snapshots


def _controller(request: Request) -> WorkspaceSnapshots:
    _authenticate(request)
    if _snapshots is None:
        raise _error(404, "Workspace snapshots are disabled")
    return _snapshots


class _Revision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    revision: str = Field(pattern=r"^[0-9a-f-]{36}$")


async def _revision(request: Request) -> str:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise _error(415, "Workspace action requires application/json")
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > 256:
            raise _error(413, "Workspace action is too large")
        body.extend(chunk)
    try:
        return _Revision.model_validate_json(bytes(body)).revision
    except ValidationError:
        raise _error(400, "Invalid workspace action") from None


@router.get("/api/workspace")
async def workspace(request: Request) -> WorkspaceView:
    _authenticate(request)  # Does not renew the approval lease.
    if _snapshots is None:
        return WorkspaceView(enabled=False)
    return await run_in_threadpool(_snapshots.view, include_files=False)


@router.get("/api/workspace/{snapshot_id}")
async def detail(snapshot_id: str, request: Request) -> SnapshotView:
    controller = _controller(request)
    try:
        return await run_in_threadpool(controller.detail, snapshot_id)
    except WorkspaceError as exc:
        raise _error(409, str(exc)) from None


@router.get("/api/workspace/{snapshot_id}/files/{file_id}")
async def preview(snapshot_id: str, file_id: str, request: Request) -> FilePreview:
    controller = _controller(request)
    try:
        return await run_in_threadpool(controller.preview, snapshot_id, file_id)
    except WorkspaceError as exc:
        raise _error(409, str(exc)) from None


@router.post("/api/workspace/{snapshot_id}/files/{file_id}/restore")
async def restore(snapshot_id: str, file_id: str, request: Request) -> SnapshotView:
    controller = _controller(request)
    revision = await _revision(request)
    try:
        return await run_in_threadpool(controller.restore, snapshot_id, file_id, revision)
    except WorkspaceError as exc:
        raise _error(409, str(exc)) from None


@router.post("/api/workspace/{snapshot_id}/discard")
async def discard(snapshot_id: str, request: Request) -> dict[str, bool]:
    controller = _controller(request)
    revision = await _revision(request)
    try:
        await run_in_threadpool(controller.discard, snapshot_id, revision)
    except WorkspaceError as exc:
        raise _error(409, str(exc)) from None
    return {"discarded": True}
