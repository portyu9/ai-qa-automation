from __future__ import annotations

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

    def fail_after_clean_closure_publication(
        self: WorkspaceLease,
        directory_fd: int | None,
    ) -> None:
        real_revalidate(self, directory_fd)
        if self is lease and self._mutation_recovery_closed:
            raise OSError("simulated failure after clean closure publication")

    with monkeypatch.context() as patch:
        patch.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_lease_root",
            fail_after_clean_closure_publication,
        )
        with pytest.raises(OSError, match="mutation recovery closure"):
            _release_guarded(lease, control)

    successor_run = artifacts / "run-successor"
    successor_run.mkdir()
    successor = WorkspaceLease(
        artifacts,
        workspace,
        "run-successor",
        run_root_identity=_identity(successor_run),
    ).acquire(publish=False)
    previous_lease = successor.previous_metadata
    successor.release()
    assert isinstance(previous_lease, dict)

    (run_dir / "runtime.json").unlink()
    recovered = recover_stale_mutation(
        artifact_root=artifacts,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="sha256:" + "0" * 64,
        recovering_run_id="run-after-ambiguous-close",
    )

    assert recovered["status"] == "BLOCKED"
    assert recovered["previous_run_id"] == "run-ambiguous-close"
