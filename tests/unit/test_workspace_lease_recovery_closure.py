from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def _identity(path: Path) -> tuple[int, int]:
    observed = path.stat(follow_symlinks=False)
    return observed.st_dev, observed.st_ino


def _lease_metadata(lease: WorkspaceLease) -> dict[str, object]:
    return json.loads(lease.path.read_text(encoding="utf-8"))


def _write_runtime(
    run_dir: Path,
    lease: WorkspaceLease,
    *,
    pending_mutation: object,
) -> None:
    (run_dir / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(lease.workspace),
                "lease_id": lease.lease_id,
                "pending_mutation": pending_mutation,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _lease_with_run_root(
    artifact_root: Path,
    workspace: Path,
    run_id: str,
) -> tuple[WorkspaceLease, Path]:
    run_dir = artifact_root / run_id
    run_dir.mkdir(parents=True)
    lease = WorkspaceLease(
        artifact_root,
        workspace,
        run_id,
        run_root_identity=_identity(run_dir),
    ).acquire()
    return lease, run_dir


def test_release_persists_recovery_closed_only_after_durable_pending_is_none(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-clean")
    published = _lease_metadata(lease)
    assert published["mutation_recovery_closed"] is False

    _write_runtime(run_dir, lease, pending_mutation=None)
    lease.release()

    closed = _lease_metadata(lease)
    assert closed["run_id"] == "run-clean"
    assert closed["lease_id"] == lease.lease_id
    assert closed["mutation_recovery_closed"] is True

    (run_dir / "runtime.json").unlink()
    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=closed,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )
    assert recovered == {"status": "NONE", "previous_run_id": "run-clean"}


def test_release_retains_open_recovery_authority_when_pending_mutation_exists(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-pending")
    _write_runtime(
        run_dir,
        lease,
        pending_mutation={"relative_path": "tests/test_target.py"},
    )
    lease.release()

    open_metadata = _lease_metadata(lease)
    assert open_metadata["mutation_recovery_closed"] is False
    (run_dir / "runtime.json").unlink()

    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=open_metadata,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )
    assert recovered["status"] == "BLOCKED"
    assert "no durable mutation-recovery closure" in str(recovered["reason"])
    assert "manual reconciliation" in str(recovered["reason"])


@pytest.mark.parametrize("closed_value", [False, None])
def test_missing_prior_runtime_without_exact_clean_closure_blocks(
    tmp_path: Path,
    closed_value: bool | None,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    prior_run = artifacts / "run-prior"
    artifacts.mkdir()
    workspace.mkdir()
    prior_run.mkdir()
    prior_identity = _identity(prior_run)
    previous_lease: dict[str, object] = {
        "run_id": "run-prior",
        "lease_id": "lease-prior",
        "workspace": str(workspace.resolve()),
        "run_root_identity": {
            "device": prior_identity[0],
            "inode": prior_identity[1],
        },
    }
    if closed_value is not None:
        previous_lease["mutation_recovery_closed"] = closed_value

    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )

    assert recovered["status"] == "BLOCKED"
    assert recovered["previous_run_id"] == "run-prior"
    assert "no durable mutation-recovery closure" in str(recovered["reason"])


def test_clean_closure_requires_exact_run_root_identity_authority(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    previous_lease = {
        "run_id": "run-prior",
        "lease_id": "lease-prior",
        "workspace": str(workspace.resolve()),
        "mutation_recovery_closed": True,
        "run_root_identity": None,
    }

    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )

    assert recovered["status"] == "BLOCKED"
    assert "lacks exact run-root identity authority" in str(recovered["reason"])


def test_invalid_clean_closure_marker_is_never_authority(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    previous_lease = {
        "run_id": "run-prior",
        "lease_id": "lease-prior",
        "workspace": str(workspace.resolve()),
        "mutation_recovery_closed": "true",
    }

    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )

    assert recovered["status"] == "BLOCKED"
    assert "closure authority is invalid" in str(recovered["reason"])


def test_missing_runtime_during_release_is_infrastructure_failure_and_unlocks(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    lease, _run_dir = _lease_with_run_root(artifacts, workspace, "run-missing-runtime")

    with pytest.raises(OSError, match="mutation recovery closure"):
        lease.release()

    assert _lease_metadata(lease)["mutation_recovery_closed"] is False

    successor_run = artifacts / "run-successor"
    successor_run.mkdir()
    successor = WorkspaceLease(
        artifacts,
        workspace,
        "run-successor",
        run_root_identity=_identity(successor_run),
    ).acquire(publish=False)
    successor.release()


def test_release_closure_persistence_failure_releases_locks_and_reports_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-failing-close")
    _write_runtime(run_dir, lease, pending_mutation=None)

    real_persist = workspace_lease_module.WorkspaceLease._persist_current_owner

    def fail_clean_close(
        self: WorkspaceLease,
        stream: object,
        directory_fd: int | None,
    ) -> None:
        if self is lease and self._mutation_recovery_closed:
            raise OSError("simulated closure persistence failure")
        real_persist(self, stream, directory_fd)

    monkeypatch.setattr(
        workspace_lease_module.WorkspaceLease,
        "_persist_current_owner",
        fail_clean_close,
    )

    with pytest.raises(OSError, match="mutation recovery closure"):
        lease.release()

    assert _lease_metadata(lease)["mutation_recovery_closed"] is False

    successor_run = artifacts / "run-successor"
    successor_run.mkdir()
    successor = WorkspaceLease(
        artifacts,
        workspace,
        "run-successor",
        run_root_identity=_identity(successor_run),
    ).acquire(publish=False)
    successor.release()
