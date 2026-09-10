from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import MutationPendingError, PendingMutation, RuntimeControl
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def _identity(path: Path) -> tuple[int, int]:
    observed = path.stat(follow_symlinks=False)
    return observed.st_dev, observed.st_ino


def _lease_metadata(lease: WorkspaceLease) -> dict[str, object]:
    return json.loads(lease.path.read_text(encoding="utf-8"))


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


def _runtime_control(
    run_dir: Path,
    lease: WorkspaceLease,
) -> tuple[RuntimeControl, RunJournal]:
    run_identity = _identity(run_dir)
    journal = RunJournal(
        run_dir / "journal.jsonl",
        max_events=1000,
        expected_parent_identity=run_identity,
    )
    control = RuntimeControl(
        workspace=lease.workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=10,
            max_mutations=10,
            max_wall_seconds=60.0,
        ),
        journal=journal,
        metadata_path=run_dir / "runtime.json",
        lease_id=lease.lease_id,
        persistence_root_identity=run_identity,
    )
    control.persist()
    return control, journal


def _release_guarded(lease: WorkspaceLease, control: RuntimeControl) -> None:
    lease.release(recovery_closure_guard=control.mutation_recovery_closure_binding)


def test_release_persists_recovery_closed_from_exact_runtime_journal_prefix(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-clean")
    control, journal = _runtime_control(run_dir, lease)
    published = _lease_metadata(lease)
    assert published["mutation_recovery_closed"] is False

    # Terminal lifecycle events may legitimately extend the durable journal after
    # RuntimeControl last persisted. Closure accepts only an exact verified prefix.
    journal.append("terminal_test_event")
    _release_guarded(lease, control)

    closed = _lease_metadata(lease)
    assert closed["run_id"] == "run-clean"
    assert closed["lease_id"] == lease.lease_id
    assert closed["mutation_recovery_closed"] is True
    runtime = json.loads((run_dir / "runtime.json").read_text(encoding="utf-8"))
    assert runtime["journal_event_count"] == 1
    assert runtime["journal_head_hash"] == journal.head_hash
    assert runtime["pending_mutation"] is None

    (run_dir / "runtime.json").unlink()
    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=closed,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-next",
    )
    assert recovered == {"status": "NONE", "previous_run_id": "run-clean"}


def test_release_rejects_forged_runtime_journal_prefix_and_unlocks(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-forged-prefix")
    control, journal = _runtime_control(run_dir, lease)
    journal.append("terminal_test_event")
    runtime_path = run_dir / "runtime.json"
    metadata = json.loads(runtime_path.read_text(encoding="utf-8"))
    metadata["journal_event_count"] = 1
    metadata["journal_head_hash"] = "0" * 64
    runtime_path.write_text(json.dumps(metadata, sort_keys=True), encoding="utf-8")

    with pytest.raises(OSError, match="mutation recovery closure"):
        _release_guarded(lease, control)

    assert _lease_metadata(lease)["mutation_recovery_closed"] is False
    with pytest.raises(MutationPendingError, match="mutation authority is closed"):
        control.assert_mutation_authority_open()

    successor_run = artifacts / "run-successor"
    successor_run.mkdir()
    successor = WorkspaceLease(
        artifacts,
        workspace,
        "run-successor",
        run_root_identity=_identity(successor_run),
    ).acquire(publish=False)
    successor.release()


def test_release_retains_open_recovery_authority_when_pending_mutation_exists(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-pending")
    control, _journal = _runtime_control(run_dir, lease)
    control.pending_mutation = PendingMutation(
        relative_path="tests/test_target.py",
        existed=False,
        backup_path=None,
        original_sha256=None,
    )
    control.persist()

    _release_guarded(lease, control)

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


def test_unguarded_generic_release_never_claims_clean_mutation_closure(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-generic")
    control, _journal = _runtime_control(run_dir, lease)
    lease.release()

    assert _lease_metadata(lease)["mutation_recovery_closed"] is False
    control.assert_mutation_authority_open()


def test_guarded_release_freezes_runtime_mutation_authority(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-frozen")
    control, _journal = _runtime_control(run_dir, lease)
    _release_guarded(lease, control)

    with pytest.raises(MutationPendingError, match="mutation authority is closed"):
        control.prepare_mutation("tests/test_after_release.py")
    with pytest.raises(MutationPendingError, match="mutation authority is closed"):
        control.bind_pending_mutation_candidate("tests/test_after_release.py", "0" * 64)
    with pytest.raises(MutationPendingError, match="mutation authority is closed"):
        control.commit_pending_mutation()
    with pytest.raises(MutationPendingError, match="mutation authority is closed"):
        control.rollback_pending_mutation(reason="must remain frozen")


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


def test_missing_runtime_during_guarded_release_is_infrastructure_failure_and_unlocks(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()
    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-missing-runtime")
    control, _journal = _runtime_control(run_dir, lease)
    (run_dir / "runtime.json").unlink()

    with pytest.raises(OSError, match="mutation recovery closure"):
        _release_guarded(lease, control)

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
    control, _journal = _runtime_control(run_dir, lease)

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
        _release_guarded(lease, control)

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
