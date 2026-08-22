from __future__ import annotations

import hashlib
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

    with pytest.raises(OSError, match="lease directory.*symlink"):
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

    with pytest.raises(OSError, match="lease file.*symlink"):
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
