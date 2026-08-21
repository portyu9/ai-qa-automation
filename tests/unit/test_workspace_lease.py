from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.workspace_lease import WorkspaceBusyError, WorkspaceLease


def test_workspace_lease_persists_metadata_outside_target(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    lease = WorkspaceLease(artifact_root, workspace, "run-123").acquire()
    try:
        assert lease.path.is_relative_to(artifact_root.resolve())
        assert not lease.path.is_relative_to(workspace.resolve())

        metadata = json.loads(lease.path.read_text(encoding="utf-8"))
        assert metadata["lease_id"] == lease.lease_id
        assert metadata["run_id"] == "run-123"
        assert metadata["workspace"] == str(workspace.resolve())
        assert isinstance(metadata["pid"], int)
        assert metadata["hostname"]
        assert metadata["acquired_at"]
    finally:
        lease.release()


def test_second_lease_is_rejected_while_first_is_held(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    first = WorkspaceLease(artifact_root, workspace, "run-a").acquire()
    second = WorkspaceLease(artifact_root, workspace, "run-b")
    try:
        with pytest.raises(WorkspaceBusyError, match="already leased"):
            second.acquire()
    finally:
        first.release()
        second.release()


def test_reacquired_lease_observes_previous_metadata(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    first = WorkspaceLease(artifact_root, workspace, "run-a").acquire()
    first_id = first.lease_id
    first.release()

    second = WorkspaceLease(artifact_root, workspace, "run-b").acquire()
    try:
        assert second.previous_metadata is not None
        assert second.previous_metadata["lease_id"] == first_id
        assert second.previous_metadata["run_id"] == "run-a"
    finally:
        second.release()
