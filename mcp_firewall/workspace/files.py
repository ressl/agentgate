"""Bounded, no-follow file operations for explicitly scoped local workspaces."""

from __future__ import annotations

import os
import stat
import time
import unicodedata
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

MAX_FILES = 1000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TREE_BYTES = 16 * 1024 * 1024
EXCLUDED = frozenset({".git", ".venv", "node_modules", "__pycache__", ".DS_Store"})


class WorkspaceError(ValueError):
    """A bounded, operator-readable error; never include private file contents."""


def identity(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)


def fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (*identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def components(path: str) -> list[str]:
    parts = path.split("/")
    if (
        not path
        or len(path.encode("utf-8", errors="replace")) > 1024
        or len(parts) > 32
        or any(part in {"", ".", ".."} | EXCLUDED for part in parts)
        or any(unicodedata.category(char).startswith("C") for char in path)
    ):
        raise WorkspaceError("Unsupported workspace path")
    return parts


@dataclass(frozen=True)
class FileState:
    data: bytes
    stamp: tuple[int, ...]

    @property
    def mode(self) -> int:
        return self.stamp[2]


@dataclass
class Tree:
    files: dict[str, FileState]
    directories: dict[str, tuple[int, int, int]]

    @property
    def size(self) -> int:
        return sum(len(item.data) for item in self.files.values())


class Workspace:
    def __init__(self, path: Path) -> None:
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise WorkspaceError("Workspace snapshots require POSIX no-follow file operations")
        self.path = path.resolve(strict=True)
        if self.path == Path(self.path.anchor):
            raise WorkspaceError("Choose a project directory, not the filesystem root")
        self._flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(self.path, self._flags)
        try:
            self._root_identity = identity(os.fstat(fd))[:2]
        finally:
            os.close(fd)

    @contextmanager
    def root(self) -> Iterator[int]:
        fd = os.open(self.path, self._flags)
        try:
            if identity(os.fstat(fd))[:2] != self._root_identity:
                raise WorkspaceError("Workspace root changed; restart with an explicit workspace")
            yield fd
        finally:
            os.close(fd)

    def _directory(self, fd: int) -> os.stat_result:
        info = os.fstat(fd)
        if info.st_dev != self._root_identity[0] or info.st_nlink == 0:
            raise WorkspaceError("Mount crossing or removed workspace directory")
        return info

    def read(self, parent: int, name: str) -> FileState | None:
        try:
            entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode):
                raise WorkspaceError("Unsupported file type or symbolic link")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_dev != self._root_identity[0]
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o7000
                or before.st_size > MAX_FILE_BYTES
            ):
                raise WorkspaceError("Unsupported file, ownership, link or file size")
            data = bytearray()
            while chunk := os.read(fd, min(65536, MAX_FILE_BYTES + 1 - len(data))):
                data.extend(chunk)
                if len(data) > MAX_FILE_BYTES:
                    raise WorkspaceError("Workspace file exceeds size limit")
            if fingerprint(before) != fingerprint(os.fstat(fd)) or len(data) != before.st_size:
                raise WorkspaceError("Workspace changed during capture; pause external writers")
            return FileState(bytes(data), fingerprint(before))
        finally:
            os.close(fd)

    def capture(self) -> Tree:
        deadline = time.monotonic() + 10

        def scan() -> Tree:
            tree = Tree({}, {})
            total = 0
            count = 0

            def walk(fd: int, prefix: str) -> None:
                nonlocal total, count
                before = self._directory(fd)
                tree.directories[prefix] = identity(before)
                # scandir is streamed: do not materialize an unbounded directory listing.
                with os.scandir(fd) as entries:
                    for entry in entries:
                        count += 1
                        if count > MAX_FILES or time.monotonic() > deadline:
                            raise WorkspaceError("Workspace exceeds entry or capture time limit")
                        if entry.name in EXCLUDED:
                            continue
                        path = prefix + "/" + entry.name if prefix else entry.name
                        components(path)
                        if entry.is_dir(follow_symlinks=False):
                            child = os.open(entry.name, self._flags, dir_fd=fd)
                            try:
                                walk(child, path)
                            finally:
                                os.close(child)
                        else:
                            item = self.read(fd, entry.name)
                            if item is None:
                                raise WorkspaceError("Workspace changed during capture")
                            total += len(item.data)
                            if total > MAX_TREE_BYTES:
                                raise WorkspaceError("Workspace exceeds total capture size limit")
                            tree.files[path] = item
                if fingerprint(before) != fingerprint(os.fstat(fd)):
                    raise WorkspaceError("Workspace directory changed during capture")

            with self.root() as fd:
                walk(fd, "")
            return tree

        first = scan()
        if first != scan():
            raise WorkspaceError("Workspace changed during capture; pause external writers")
        return first

    @contextmanager
    def parent(self, path: str, tree: Tree) -> Iterator[tuple[int, str]]:
        parts = components(path)
        with self.root() as root:
            fd = os.dup(root)
            try:
                prefix = ""
                for part in parts[:-1]:
                    if identity(self._directory(fd)) != tree.directories.get(prefix):
                        raise WorkspaceError("Workspace parent changed")
                    child = os.open(part, self._flags, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    prefix = prefix + "/" + part if prefix else part
                if identity(self._directory(fd)) != tree.directories.get(prefix):
                    raise WorkspaceError("Workspace parent changed")
                yield fd, parts[-1]
            finally:
                os.close(fd)

    def restore(self, path: str, before: FileState | None, after: Tree) -> None:
        with self.parent(path, after) as (parent, name):
            expected = after.files.get(path)
            if self.read(parent, name) != expected:
                raise WorkspaceError("File changed since capture; current file was preserved")
            temporary = ".mcp-firewall-restore-" + uuid.uuid4().hex
            try:
                if before is not None:
                    fd = os.open(
                        temporary,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=parent,
                    )
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(before.data)
                        stream.flush()
                        os.fchmod(stream.fileno(), before.mode)
                        os.fsync(stream.fileno())
                # Reopen the whole chain and compare immediately before mutation.
                with self.parent(path, after) as (checked, _):
                    if (
                        identity(os.fstat(checked)) != identity(os.fstat(parent))
                        or self.read(checked, name) != expected
                    ):
                        raise WorkspaceError(
                            "File changed during restore; current file was preserved"
                        )
                    if before is None:
                        os.unlink(name, dir_fd=checked)
                    elif expected is None:
                        # Creating a deleted file must never overwrite a concurrently created file.
                        os.link(
                            temporary,
                            name,
                            src_dir_fd=parent,
                            dst_dir_fd=checked,
                            follow_symlinks=False,
                        )
                    else:
                        os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=checked)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
