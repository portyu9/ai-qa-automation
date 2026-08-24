from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def test_workspace_lease_rejects_symlinked_lease_directory(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    outside = tmp_path / "outside-leases"
    outside.mkdir()
    lease_root = artifact_root / ".leases"
    try:
        lease_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(OSError, match=r"lease directory.*symlink"):
        WorkspaceLease(artifact_root, workspace, "run-1")

    assert list(outside.iterdir()) == []


def test_workspace_lease_rejects_symlinked_lock_file(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    lease_root = artifact_root / ".leases"
    lease_root.mkdir(parents=True)
    workspace = tmp_path / "sut"
    workspace.mkdir()
    key = hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()[:24]
    lock_path = lease_root / f"{key}.lock"
    outside = tmp_path / "outside.lock"
    outside.write_text("do not modify\n", encoding="utf-8")
    try:
        lock_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(OSError, match=r"lease file.*symlink"):
        WorkspaceLease(artifact_root, workspace, "run-1")

    assert outside.read_text(encoding="utf-8") == "do not modify\n"


def test_workspace_lease_rechecks_file_ownership_before_acquire(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    subject = WorkspaceLease(artifact_root, workspace, "run-1")
    outside = tmp_path / "outside.lock"
    outside.write_text("do not modify\n", encoding="utf-8")
    try:
        subject.path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(OSError, match="symlink ownership"):
        subject.acquire()

    assert outside.read_text(encoding="utf-8") == "do not modify\n"


def test_workspace_lease_descriptor_capability_survives_os_open_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    subject = WorkspaceLease(artifact_root, workspace, "run-1")
    if not subject._supports_descriptor_relative_lease_open():
        pytest.skip("descriptor-relative no-follow lease open unavailable")

    real_open = os.open

    def wrapped_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", wrapped_open)

    assert subject._supports_descriptor_relative_lease_open() is True


def test_workspace_lease_rejects_regular_directory_replacement_before_acquire(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    subject = WorkspaceLease(artifact_root, workspace, "run-1")

    lease_root = subject.path.parent
    original_root = artifact_root / ".leases-original"
    lease_root.rename(original_root)
    lease_root.mkdir()

    with pytest.raises(OSError, match="lease directory changed identity"):
        subject.acquire()

    assert list(lease_root.iterdir()) == []


def test_workspace_lease_rejects_directory_swap_during_lock_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    subject = WorkspaceLease(artifact_root, workspace, "run-1")
    if not subject._supports_descriptor_relative_lease_open():
        pytest.skip("descriptor-relative no-follow lease open unavailable")

    lease_root = subject.path.parent
    original_root = artifact_root / ".leases-original"
    replacement_root = tmp_path / "replacement-leases"
    replacement_root.mkdir()
    real_open = os.open
    swapped = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if not swapped and dir_fd is None and Path(path) == lease_root:
            directory_fd = real_open(path, flags, mode)
            lease_root.rename(original_root)
            try:
                lease_root.symlink_to(replacement_root, target_is_directory=True)
            except OSError as exc:  # pragma: no cover - platform/filesystem capability
                os.close(directory_fd)
                pytest.skip(f"symlink creation unavailable: {exc}")
            swapped = True
            return directory_fd
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)

    with pytest.raises(OSError, match="lease directory changed identity"):
        subject.acquire()

    assert swapped is True
    assert list(replacement_root.iterdir()) == []
