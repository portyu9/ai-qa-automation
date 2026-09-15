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

    if release_failed:
        assert recovered["status"] == "BLOCKED"
        assert recovered["previous_run_id"] == "run-ambiguous-close"
    else:
        assert previous_lease["mutation_recovery_closed"] is True
        assert recovered == {"status": "NONE", "previous_run_id": "run-ambiguous-close"}
