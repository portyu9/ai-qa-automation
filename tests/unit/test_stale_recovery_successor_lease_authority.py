from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ai_qa_automation.runtime.stale_recovery as stale_recovery_module
from ai_qa_automation.fs_authority import (
    bind_pending_root_authority,
    clear_pending_root_authority,
    descriptor_relative_authority_supported,
    pending_root_authority,
)
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def _identity(path: Path) -> tuple[int, int]:
    status = path.stat(follow_symlinks=False)
    return status.st_dev, status.st_ino


def _setup_residual_authority(
    tmp_path: Path,
) -> tuple[Path, Path, tuple[int, int], dict[str, Any], str]:
    if not descriptor_relative_authority_supported():
        pytest.skip("successor lease authority tests require descriptor-relative support")

    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    prior_run_identity = _identity(prior_run)
    workspace_identity = _identity(workspace)

    prior = WorkspaceLease(
        artifact_root,
        workspace,
        "run-old",
        run_root_identity=prior_run_identity,
    ).acquire()
    prior_lease_id = prior.lease_id
    lease_path = prior.path
    prior.release()
    previous_lease = json.loads(lease_path.read_text(encoding="utf-8"))

    runtime = {
        "lease_id": prior_lease_id,
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_identity[0],
            "inode": workspace_identity[1],
        },
        "workspace_fingerprint": "sha256:" + "a" * 64,
        "pending_mutation": None,
    }
    (prior_run / "runtime.json").write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    bind_pending_root_authority(workspace, workspace_identity, owner=prior_lease_id)
    return artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id


def _recover(
    *,
    artifact_root: Path,
    workspace: Path,
    previous_lease: dict[str, Any],
    recovering_run_id: str = "run-new",
    recovery_lease: WorkspaceLease | None = None,
) -> dict[str, Any]:
    return recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "a" * 64,
        recovering_run_id=recovering_run_id,
        recovery_lease=recovery_lease,
    )


def _clear_fixture_authority(
    workspace: Path,
    workspace_identity: tuple[int, int],
    prior_lease_id: str,
) -> None:
    assert clear_pending_root_authority(
        workspace,
        workspace_identity,
        owner=prior_lease_id,
    )


def test_direct_recovery_without_successor_lease_cannot_clear_residual_authority(
    tmp_path: Path,
) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
        )

        assert result["status"] == "BLOCKED"
        assert "live deferred successor" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_unacquired_successor_lease_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new")
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "not acquired" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_released_successor_lease_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    successor.release()
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "not acquired" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_published_successor_lease_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    successor.publish_current_owner()
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "already published" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_wrong_run_successor_lease_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovering_run_id="run-other",
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "different run" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_wrong_workspace_successor_lease_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    other_workspace = tmp_path / "other-sut"
    other_workspace.mkdir()
    wrong_successor = WorkspaceLease(artifact_root, other_workspace, "run-new").acquire(
        publish=False
    )
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovery_lease=wrong_successor,
        )

        assert result["status"] == "BLOCKED"
        assert "different workspace" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        wrong_successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_wrong_predecessor_handoff_cannot_clear_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    forged_previous = dict(previous_lease)
    forged_previous["hostname"] = "forged-predecessor"
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=forged_previous,
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "predecessor handoff" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_mutated_live_predecessor_metadata_cannot_bypass_successor_authority(
    tmp_path: Path,
) -> None:
    artifact_root, workspace, workspace_identity, _previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    mutated_previous = successor.previous_metadata
    assert mutated_previous is not None
    mutated_previous["run_id"] = "run-new"
    try:
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=mutated_previous,
            recovery_lease=successor,
        )

        assert result["status"] == "BLOCKED"
        assert "predecessor handoff" in str(result["reason"])
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_recovery_body_infrastructure_failure_is_not_laundered_as_invalid_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)

    def fail_after_authority(**_kwargs: object) -> dict[str, Any]:
        raise OSError("simulated recovery infrastructure failure")

    monkeypatch.setattr(
        stale_recovery_module,
        "_recover_stale_mutation_authorized",
        fail_after_authority,
    )
    try:
        with pytest.raises(OSError, match="simulated recovery infrastructure failure"):
            _recover(
                artifact_root=artifact_root,
                workspace=workspace,
                previous_lease=previous_lease,
                recovery_lease=successor,
            )
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        successor.release()
        _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)


def test_exact_deferred_successor_lease_reconciles_residual_authority(tmp_path: Path) -> None:
    artifact_root, workspace, workspace_identity, previous_lease, prior_lease_id = (
        _setup_residual_authority(tmp_path)
    )
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    try:
        assert successor.previous_metadata == previous_lease
        result = _recover(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            recovery_lease=successor,
        )

        assert result == {"status": "NONE", "previous_run_id": "run-old"}
        assert pending_root_authority(workspace) is None
    finally:
        successor.release()
        if pending_root_authority(workspace) is not None:
            _clear_fixture_authority(workspace, workspace_identity, prior_lease_id)
