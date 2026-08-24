from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def test_workspace_lease_rejects_target_root_replacement_before_acquire(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    lease = WorkspaceLease(artifact_root, workspace, "run-1")

    original_workspace = tmp_path / "sut-original"
    workspace.rename(original_workspace)
    workspace.mkdir()

    with pytest.raises(OSError, match="target workspace changed identity"):
        lease.acquire()

    assert not lease.path.exists()


def test_workspace_lease_persists_authorized_target_root_identity(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    lease = WorkspaceLease(artifact_root, workspace, "run-1")
    expected = lease.workspace_root_identity
    assert expected is not None

    with lease:
        metadata = json.loads(lease.path.read_text(encoding="utf-8"))

    assert metadata["workspace_root_identity"] == {
        "device": expected[0],
        "inode": expected[1],
    }
