"""Opt-in, session-local workspace snapshots and selected-file recovery."""

from __future__ import annotations

import difflib
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ..events import sanitize_text
from .files import MAX_TREE_BYTES, Tree, Workspace, WorkspaceError

MAX_RECORDS = 8
MAX_RETAINED_BYTES = 128 * 1024 * 1024


class Change(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    path: str
    kind: Literal["added", "modified", "deleted"]
    restored: bool = False


class SnapshotView(BaseModel):
    id: str
    revision: str
    session_id: str
    call_id: str
    tool: str
    created_at: float
    state: Literal["inflight", "complete", "incomplete"]
    message: str
    files: list[Change]
    file_count: int = 0


class WorkspaceView(BaseModel):
    enabled: bool
    workspace: str = ""
    busy: bool = False
    snapshots: list[SnapshotView] = []


class FilePreview(BaseModel):
    snapshot_id: str
    revision: str
    file_id: str
    path: str
    diff: str
    omitted: bool


@dataclass
class _Record:
    view: SnapshotView
    before: Tree
    after: Tree | None = None


class WorkspaceSnapshots:
    """Thread-safe controller shared by the stdio proxy and authenticated local UI.

    File bytes never enter integration events or audit. External writers must be
    paused for restoration; this is not a filesystem sandbox or multi-file transaction.
    """

    def __init__(self, path: Path) -> None:
        self.workspace = Workspace(path)
        self._lock = threading.RLock()
        self._records: dict[str, _Record] = {}
        self._active: str | None = None

    def view(self, *, include_files: bool = True) -> WorkspaceView:
        with self._lock:
            return WorkspaceView(
                enabled=True,
                workspace=str(self.workspace.path),
                busy=self._active is not None,
                snapshots=[
                    item.view.model_copy(deep=True, update={} if include_files else {"files": []})
                    for item in reversed(self._records.values())
                ],
            )

    def begin(self, session_id: str, call_id: str, tool: str) -> None:
        with self._lock:
            retained = sum(
                item.before.size + (item.after.size if item.after else 0)
                for item in self._records.values()
            )
            if self._active is not None:
                raise WorkspaceError("A workspace tool call is still in flight")
            if (
                len(self._records) >= MAX_RECORDS
                or retained + 2 * MAX_TREE_BYTES > MAX_RETAINED_BYTES
            ):
                raise WorkspaceError(
                    "Snapshot capacity reached; explicitly discard a completed record"
                )
            try:
                before = self.workspace.capture()
            except OSError:
                raise WorkspaceError(
                    "Workspace capture failed; check file types and access"
                ) from None
            key = str(uuid.uuid4())
            self._records[key] = _Record(
                SnapshotView(
                    id=key,
                    revision=str(uuid.uuid4()),
                    session_id=session_id,
                    call_id=call_id,
                    tool=sanitize_text(tool),
                    created_at=time.time(),
                    state="inflight",
                    message="Before capture saved; awaiting correlated response",
                    files=[],
                ),
                before,
            )
            self._active = key

    def finish(self, call_id: str, *, complete: bool = True) -> None:
        with self._lock:
            if self._active is None:
                return
            item = self._records[self._active]
            if item.view.call_id != call_id:
                return
            try:
                if not complete:
                    raise WorkspaceError(
                        "Response missing; file outcome and background work are unknown"
                    )
                item.after = self.workspace.capture()
                changes = []
                for path in sorted(item.before.files.keys() | item.after.files.keys()):
                    before, after = item.before.files.get(path), item.after.files.get(path)
                    if before and after and before.data == after.data and before.mode == after.mode:
                        continue
                    changes.append(
                        Change(
                            id=str(uuid.uuid4()),
                            path=path,
                            kind="added"
                            if before is None
                            else "deleted"
                            if after is None
                            else "modified",
                        )
                    )
                item.view.files = changes
                item.view.file_count = len(changes)
                item.view.state = "complete"
                item.view.message = (
                    "Changes observed during call; attribution and background work unverified"
                )
            except (OSError, WorkspaceError):
                item.after = None
                item.view.state = "incomplete"
                item.view.message = (
                    "Post-capture unavailable or response missing; restore is disabled"
                )
            finally:
                item.view.revision = str(uuid.uuid4())
                self._active = None

    def _record(self, key: str, revision: str | None = None) -> _Record:
        item = self._records.get(key)
        if item is None:
            raise WorkspaceError("Snapshot is no longer available")
        if revision is not None and item.view.revision != revision:
            raise WorkspaceError("Snapshot changed; review it again")
        return item

    def detail(self, key: str) -> SnapshotView:
        with self._lock:
            return self._record(key).view.model_copy(deep=True)

    @staticmethod
    def _change(item: _Record, file_id: str) -> Change:
        change = next((change for change in item.view.files if change.id == file_id), None)
        if change is None or change.restored:
            raise WorkspaceError("File is unavailable or already restored")
        return change

    def preview(self, key: str, file_id: str) -> FilePreview:
        with self._lock:
            item = self._record(key)
            change = self._change(item, file_id)
            if item.after is None:
                raise WorkspaceError("Snapshot has no complete post-capture")
            before, after = item.before.files.get(change.path), item.after.files.get(change.path)
            first, last = before.data if before else b"", after.data if after else b""
            omitted = False
            diff = ""
            try:
                if max(len(first), len(last)) > 65536 or b"\0" in first + last:
                    raise ValueError
                left, right = first.decode("utf-8"), last.decode("utf-8")
                if max(left.count("\n"), right.count("\n")) > 2000:
                    raise ValueError
                lines = difflib.unified_diff(
                    left.splitlines(keepends=True),
                    right.splitlines(keepends=True),
                    fromfile="before",
                    tofile="after",
                )
                diff = "".join(
                    line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                    for line in lines
                )
                modes = (
                    f"Mode: {oct(before.mode) if before else 'absent'} → "
                    f"{oct(after.mode) if after else 'absent'}\n"
                )
                diff = modes + diff
                if len(diff.encode()) > 65536:
                    raise ValueError
            except (UnicodeError, ValueError):
                diff = "Preview omitted: binary or large text. Exact bytes are retained locally."
                omitted = True
            return FilePreview(
                snapshot_id=key,
                revision=item.view.revision,
                file_id=file_id,
                path=change.path,
                diff=diff,
                omitted=omitted,
            )

    def restore(self, key: str, file_id: str, revision: str) -> SnapshotView:
        with self._lock:
            if self._active is not None:
                raise WorkspaceError("Wait for the active tool call before restoring")
            item = self._record(key, revision)
            change = self._change(item, file_id)
            if item.after is None:
                raise WorkspaceError("Snapshot has no complete post-capture")
            try:
                self.workspace.restore(change.path, item.before.files.get(change.path), item.after)
            except OSError:
                raise WorkspaceError(
                    "File or parent changed or is inaccessible; review the workspace"
                ) from None
            item.view.files = [
                entry.model_copy(update={"restored": True}) if entry.id == file_id else entry
                for entry in item.view.files
            ]
            item.view.revision = str(uuid.uuid4())
            item.view.message = (
                "Selected file restored; no claim of tool or external-action rollback"
            )
            return item.view.model_copy(deep=True)

    def discard(self, key: str, revision: str) -> None:
        with self._lock:
            item = self._record(key, revision)
            if item.view.state == "inflight":
                raise WorkspaceError("An in-flight snapshot cannot be discarded")
            del self._records[key]
