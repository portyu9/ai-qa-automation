from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from tests.unit.test_workspace_lease_recovery_closure import (
    _identity,
    _lease_with_run_root,
    _release_guarded,
    _runtime_control,
)


def _fresh_previous_lease(
    artifacts: Path,
    workspace: Path,
    *,
    run_id: str,
) -> dict[str, object]:
    successor_run = artifacts / run_id
    successor_run.mkdir()
    successor = WorkspaceLease(
        artifacts,
        workspace,
        run_id,
        run_root_identity=_identity(successor_run),
    ).acquire(publish=False)
    previous_lease = successor.previous_metadata
    successor.release()
    assert isinstance(previous_lease, dict)
    return previous_lease


def _recover_without_runtime(
    *,
    artifacts: Path,
    workspace: Path,
    run_dir: Path,
    previous_lease: dict[str, object],
    recovering_run_id: str,
) -> dict[str, object]:
    (run_dir / "runtime.json").unlink()
    return recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id=recovering_run_id,
    )


def test_failed_post_publication_clean_closure_cannot_authorize_missing_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-ambiguous-close")
    control, _journal = _runtime_control(run_dir, lease)
    assert lease.path.is_file()

    real_revalidate = workspace_lease_module.WorkspaceLease._revalidate_lease_root
    post_publication_failure_injected = False

    def fail_once_after_clean_closure_publication(
        self: WorkspaceLease,
        directory_fd: int | None,
    ) -> None:
        nonlocal post_publication_failure_injected
        real_revalidate(self, directory_fd)
        if (
            self is lease
            and self._mutation_recovery_closed
            and not post_publication_failure_injected
        ):
            post_publication_failure_injected = True
            raise OSError("simulated failure after clean closure publication")

    release_failed = False
    with monkeypatch.context() as patch:
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_lease_root",
            fail_once_after_clean_closure_publication,
        )
        try:
            _release_guarded(lease, control)
        except OSError as exc:
            assert "mutation recovery closure" in str(exc)
            release_failed = True

    assert post_publication_failure_injected is True
    previous_lease = _fresh_previous_lease(
        artifacts,
        workspace,
        run_id="run-successor",
    )
    recovered = _recover_without_runtime(
        artifacts=artifacts,
        workspace=workspace,
        run_dir=run_dir,
        previous_lease=previous_lease,
        recovering_run_id="run-after-ambiguous-close",
    )

    if release_failed:
        assert recovered["status"] == "BLOCKED"
        assert recovered["previous_run_id"] == "run-ambiguous-close"
    else:
        assert previous_lease["mutation_recovery_closed"] is True
        assert recovered == {"status": "NONE", "previous_run_id": "run-ambiguous-close"}


def test_unreconciled_clean_closure_publication_restores_previous_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-rollback-close")
    control, _journal = _runtime_control(run_dir, lease)
    real_revalidate = workspace_lease_module.WorkspaceLease._revalidate_lease_root
    real_reconcile = workspace_lease_module.WorkspaceLease._reconcile_persisted_owner
    post_publication_failure_injected = False

    def fail_once_after_clean_closure_publication(
        self: WorkspaceLease,
        directory_fd: int | None,
    ) -> None:
        nonlocal post_publication_failure_injected
        real_revalidate(self, directory_fd)
        if (
            self is lease
            and self._mutation_recovery_closed
            and not post_publication_failure_injected
        ):
            post_publication_failure_injected = True
            raise OSError("simulated unreconciled clean closure publication")

    def refuse_clean_closure_reconciliation(
        self: WorkspaceLease,
        stream: object,
        directory_fd: int | None,
        expected: bytes,
    ) -> bool:
        payload = json.loads(expected.decode("utf-8"))
        if payload.get("mutation_recovery_closed") is True:
            return False
        return real_reconcile(self, stream, directory_fd, expected)

    with monkeypatch.context() as patch:
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_lease_root",
            fail_once_after_clean_closure_publication,
        )
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_reconcile_persisted_owner",
            refuse_clean_closure_reconciliation,
        )
        with pytest.raises(OSError, match="mutation recovery closure"):
            _release_guarded(lease, control)

    assert post_publication_failure_injected is True
    previous_lease = _fresh_previous_lease(
        artifacts,
        workspace,
        run_id="run-successor-after-rollback",
    )
    assert previous_lease["mutation_recovery_closed"] is False
    recovered = _recover_without_runtime(
        artifacts=artifacts,
        workspace=workspace,
        run_dir=run_dir,
        previous_lease=previous_lease,
        recovering_run_id="run-after-rollback-close",
    )
    assert recovered["status"] == "BLOCKED"
    assert recovered["previous_run_id"] == "run-rollback-close"


def test_persistent_post_publication_validation_failure_restores_previous_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-persistent-close")
    control, _journal = _runtime_control(run_dir, lease)
    real_revalidate = workspace_lease_module.WorkspaceLease._revalidate_lease_root
    closure_revalidations = 0

    def fail_after_clean_closure_bytes_are_published(
        self: WorkspaceLease,
        directory_fd: int | None,
    ) -> None:
        nonlocal closure_revalidations
        if self is lease and self._mutation_recovery_closed:
            closure_revalidations += 1
            if closure_revalidations >= 2:
                raise OSError("simulated persistent post-publication validation failure")
        real_revalidate(self, directory_fd)

    with monkeypatch.context() as patch:
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_lease_root",
            fail_after_clean_closure_bytes_are_published,
        )
        with pytest.raises(OSError, match="mutation recovery closure"):
            _release_guarded(lease, control)

    assert closure_revalidations >= 2
    previous_lease = _fresh_previous_lease(
        artifacts,
        workspace,
        run_id="run-successor-after-persistent-failure",
    )
    assert previous_lease["mutation_recovery_closed"] is False
    recovered = _recover_without_runtime(
        artifacts=artifacts,
        workspace=workspace,
        run_dir=run_dir,
        previous_lease=previous_lease,
        recovering_run_id="run-after-persistent-close",
    )
    assert recovered["status"] == "BLOCKED"
    assert recovered["previous_run_id"] == "run-persistent-close"


def test_interrupted_clean_closure_publication_restores_previous_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    artifacts.mkdir()
    workspace.mkdir()

    lease, run_dir = _lease_with_run_root(artifacts, workspace, "run-interrupted-close")
    control, _journal = _runtime_control(run_dir, lease)
    real_revalidate = workspace_lease_module.WorkspaceLease._revalidate_lease_root
    post_publication_interrupt_injected = False

    def interrupt_once_after_clean_closure_publication(
        self: WorkspaceLease,
        directory_fd: int | None,
    ) -> None:
        nonlocal post_publication_interrupt_injected
        real_revalidate(self, directory_fd)
        if (
            self is lease
            and self._mutation_recovery_closed
            and not post_publication_interrupt_injected
        ):
            post_publication_interrupt_injected = True
            raise KeyboardInterrupt("simulated interruption after clean closure publication")

    with monkeypatch.context() as patch:
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_lease_root",
            interrupt_once_after_clean_closure_publication,
        )
        with pytest.raises(KeyboardInterrupt, match="clean closure publication"):
            _release_guarded(lease, control)

    assert post_publication_interrupt_injected is True
    previous_lease = _fresh_previous_lease(
        artifacts,
        workspace,
        run_id="run-successor-after-interrupt",
    )
    assert previous_lease["mutation_recovery_closed"] is False
    recovered = _recover_without_runtime(
        artifacts=artifacts,
        workspace=workspace,
        run_dir=run_dir,
        previous_lease=previous_lease,
        recovering_run_id="run-after-interrupted-close",
    )
    assert recovered["status"] == "BLOCKED"
    assert recovered["previous_run_id"] == "run-interrupted-close"
