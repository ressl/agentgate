"""Recovery must preserve later edits and never follow untrusted file paths."""

import os
import stat
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from mcp_firewall.workspace import WorkspaceSnapshots
from mcp_firewall.workspace import files as fs
from mcp_firewall.workspace.files import WorkspaceError


@pytest.fixture
def workspace(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    return root, WorkspaceSnapshots(root)


def begin(manager):
    call = str(uuid.uuid4())
    manager.begin(str(uuid.uuid4()), call, "edit")
    return call


def record(manager):
    return manager.view().snapshots[0]


def restore(manager, item, path):
    change = next(change for change in item.files if change.path == path)
    return manager.restore(item.id, change.id, item.revision)


def test_selected_modified_added_deleted_and_binary_files(workspace):
    root, manager = workspace
    (root / "a.txt").write_text("before\n")
    (root / "deleted").write_bytes(b"\0binary")
    os.chmod(root / "a.txt", 0o640)
    call = begin(manager)
    (root / "a.txt").write_text("after\n")
    os.chmod(root / "a.txt", 0o600)
    (root / "deleted").unlink()
    (root / "added").write_text("new")
    manager.finish(call)
    item = record(manager)
    assert [(c.path, c.kind) for c in item.files] == [
        ("a.txt", "modified"),
        ("added", "added"),
        ("deleted", "deleted"),
    ]
    preview = manager.preview(item.id, item.files[0].id)
    assert "-before" in preview.diff and "+after" in preview.diff
    assert not preview.omitted
    assert manager.preview(item.id, item.files[2].id).omitted
    item = restore(manager, item, "a.txt")
    assert (root / "a.txt").read_text() == "before\n"
    assert stat.S_IMODE((root / "a.txt").stat().st_mode) == 0o640
    assert (root / "added").exists() and not (root / "deleted").exists()
    item = restore(manager, item, "added")
    assert not (root / "added").exists()
    restore(manager, item, "deleted")
    assert (root / "deleted").read_bytes() == b"\0binary"
    assert (root / "deleted").stat().st_nlink == 1
    assert all(c.restored for c in record(manager).files)


@pytest.mark.parametrize(
    "later", ["content", "mode", "touch", "replace", "symlink", "hardlink", "missing"]
)
def test_later_changes_are_preserved(workspace, later):
    root, manager = workspace
    target = root / "file"
    target.write_text("before")
    call = begin(manager)
    target.write_text("tool")
    manager.finish(call)
    if later == "content":
        target.write_text("user")
    elif later == "mode":
        target.chmod(0o400)
    elif later == "touch":
        target.touch()
    elif later == "replace":
        target.unlink()
        target.write_text("tool")
    elif later in {"symlink", "hardlink"}:
        outside = root.parent / "outside"
        outside.write_text("outside")
        target.unlink()
        if later == "symlink":
            target.symlink_to(outside)
        else:
            os.link(outside, target)
    else:
        target.unlink()
    expected = target.read_bytes() if target.exists() else None
    with pytest.raises(WorkspaceError):
        restore(manager, record(manager), "file")
    assert (target.read_bytes() if target.exists() else None) == expected
    assert not list(root.glob(".mcp-firewall-restore-*"))


def test_stale_revision_and_concurrent_restore_apply_once(workspace):
    root, manager = workspace
    (root / "file").write_text("before")
    call = begin(manager)
    (root / "file").write_text("tool")
    manager.finish(call)
    item = record(manager)

    def attempt():
        try:
            restore(manager, item, "file")
            return True
        except WorkspaceError:
            return False

    with ThreadPoolExecutor(2) as executor:
        assert sorted(executor.map(lambda _: attempt(), range(2))) == [False, True]
    with pytest.raises(WorkspaceError):
        manager.discard(item.id, item.revision)
    manager.discard(item.id, record(manager).revision)
    assert manager.view().snapshots == []


@pytest.mark.parametrize("swap", ["symlink", "replacement", "removed"])
def test_changed_parent_never_reaches_outside(workspace, swap):
    root, manager = workspace
    parent = root / "dir"
    parent.mkdir()
    (parent / "file").write_text("before")
    call = begin(manager)
    (parent / "file").write_text("tool")
    manager.finish(call)
    parent.rename(root.parent / "moved")
    if swap == "symlink":
        parent.symlink_to(root.parent / "moved")
    elif swap == "replacement":
        parent.mkdir()
        (parent / "file").write_text("user")
    with pytest.raises(WorkspaceError):
        restore(manager, record(manager), "dir/file")
    assert (root.parent / "moved/file").read_text() == "tool"
    if swap == "replacement":
        assert (parent / "file").read_text() == "user"


def test_root_replacement_and_missing_response_disable_recovery(workspace):
    root, manager = workspace
    (root / "file").write_text("before")
    call = begin(manager)
    root.rename(root.parent / "moved")
    root.mkdir()
    (root / "file").write_text("user")
    manager.finish(call)
    assert record(manager).state == "incomplete"
    assert not manager.view().busy
    with pytest.raises(WorkspaceError):
        begin(manager)
    assert (root / "file").read_text() == "user"


def test_active_and_missing_response(workspace):
    root, manager = workspace
    call = begin(manager)
    item = record(manager)
    with pytest.raises(WorkspaceError):
        begin(manager)
    with pytest.raises(WorkspaceError):
        manager.discard(item.id, item.revision)
    manager.finish("unrelated")
    assert manager.view().busy
    manager.finish(call, complete=False)
    assert record(manager).state == "incomplete" and not manager.view().busy
    manager.discard(item.id, record(manager).revision)


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "fifo", "file-size", "total-size", "entries"]
)
def test_unsafe_capture_fails_before_admission(workspace, monkeypatch, kind):
    root, manager = workspace
    outside = root.parent / "outside"
    outside.write_text("outside")
    if kind == "symlink":
        (root / "file").symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, root / "file")
    elif kind == "fifo":
        os.mkfifo(root / "file")
    elif kind == "file-size":
        monkeypatch.setattr(fs, "MAX_FILE_BYTES", 3)
        (root / "file").write_text("1234")
    elif kind == "total-size":
        monkeypatch.setattr(fs, "MAX_TREE_BYTES", 3)
        (root / "file").write_text("1234")
    else:
        monkeypatch.setattr(fs, "MAX_FILES", 1)
        (root / "one").touch()
        (root / "two").touch()
    with pytest.raises(WorkspaceError):
        begin(manager)
    assert manager.view().snapshots == []
    assert outside.read_text() == "outside"


def test_retention_is_explicit_and_exclusions_do_not_follow_links(workspace):
    root, manager = workspace
    (root / ".git").symlink_to(root.parent)
    for _ in range(8):
        manager.finish(begin(manager))
    assert len(manager.view().snapshots) == 8
    with pytest.raises(WorkspaceError, match="capacity"):
        begin(manager)
    item = record(manager)
    manager.discard(item.id, item.revision)
    manager.finish(begin(manager))


@pytest.mark.parametrize(
    "path", ["../escape", "/absolute", "a//b", ".git/config", "a/../b", "a\nspoof"]
)
def test_path_validation(path):
    with pytest.raises(WorkspaceError):
        fs.components(path)


def test_busy_restore_and_new_file_conflict(workspace):
    root, manager = workspace
    target = root / "file"
    target.write_text("before")
    call = begin(manager)
    target.unlink()
    manager.finish(call)
    item = record(manager)
    call = begin(manager)
    with pytest.raises(WorkspaceError, match="active"):
        restore(manager, item, "file")
    manager.finish(call)
    target.write_text("user")
    with pytest.raises(WorkspaceError):
        restore(manager, item, "file")
    assert target.read_text() == "user"


def test_diff_explains_missing_newline(workspace):
    root, manager = workspace
    (root / "file").write_text("before")
    call = begin(manager)
    (root / "file").write_text("after")
    manager.finish(call)
    item = record(manager)
    diff = manager.preview(item.id, item.files[0].id).diff
    assert "-before\n\\ No newline at end of file\n+after\n" in diff


def test_deleted_file_create_race_cannot_overwrite_user_file(workspace, monkeypatch):
    root, manager = workspace
    target = root / "file"
    target.write_text("before")
    call = begin(manager)
    target.unlink()
    manager.finish(call)
    link = os.link

    def racing_link(*args, **kwargs):
        target.write_text("user won race")
        return link(*args, **kwargs)

    monkeypatch.setattr(os, "link", racing_link)
    with pytest.raises(WorkspaceError):
        restore(manager, record(manager), "file")
    assert target.read_text() == "user won race"
    assert not list(root.glob(".mcp-firewall-restore-*"))


def test_restore_rechecks_after_staging(workspace, monkeypatch):
    root, manager = workspace
    target = root / "file"
    target.write_text("before")
    call = begin(manager)
    target.write_text("tool")
    manager.finish(call)
    fsync = os.fsync

    def edited_during_staging(fd):
        target.write_text("user during staging")
        fsync(fd)

    monkeypatch.setattr(os, "fsync", edited_during_staging)
    with pytest.raises(WorkspaceError):
        restore(manager, record(manager), "file")
    assert target.read_text() == "user during staging"
    assert not list(root.glob(".mcp-firewall-restore-*"))
