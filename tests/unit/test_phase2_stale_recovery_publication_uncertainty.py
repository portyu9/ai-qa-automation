from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ai_qa_automation.runtime._stale_recovery_legacy as stale_recovery_legacy_module
from ai_qa_automation.runtime.run_control import atomic_write_json as runtime_atomic_write_json
from tests.unit.stale_recovery_lease_helpers import recover_with_deferred_successor
from tests.unit.test_stale_recovery_journal_resume import (
    _setup_pending_recovery,
    _workspace_fingerprint,
)


def test_post_publication_stale_recovery_close_cannot_be_accepted_as_none_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup_pending_recovery(tmp_path)
    runtime_path = setup["runtime_path"]
    workspace = setup["workspace"]
    backup = setup["backup"]
    previous_lease = setup["previous_lease"]
    assert isinstance(runtime_path, Path)
    assert isinstance(workspace, Path)
    assert isinstance(backup, Path)
    assert isinstance(previous_lease, dict)
    assert previous_lease["mutation_recovery_closed"] is False

    final_close_published = False

    def publish_then_fail(
        path: Path,
        payload: dict[str, Any],
        *,
        expected_parent_identity: tuple[int, int] | None = None,
        on_uncertain: Any = None,
    ) -> None:
        nonlocal final_close_published
        runtime_atomic_write_json(
            path,
            payload,
            expected_parent_identity=expected_parent_identity,
            on_uncertain=on_uncertain,
        )
        if payload.get("pending_mutation") is None and "recovered_by_run_id" in payload:
            final_close_published = True
            raise OSError("simulated failure after stale recovery metadata publication")

    with monkeypatch.context() as patch:
        patch.setattr(
            stale_recovery_legacy_module,
            "atomic_write_json",
            publish_then_fail,
        )
        first = recover_with_deferred_successor(
            artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
            workspace=workspace,
            previous_lease=previous_lease,
            current_workspace_fingerprint=setup["candidate_fingerprint"],  # type: ignore[arg-type]
            recovering_run_id="run-recovery-1",
        )

    assert first["status"] == "BLOCKED"
    assert "recovery metadata could not be durably closed" in str(first["reason"])
    assert final_close_published is True
    assert backup.is_file()

    published = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert published["pending_mutation"] is None
    assert published["recovered_by_run_id"] == "run-recovery-1"
    assert previous_lease["mutation_recovery_closed"] is False

    recovered_fingerprint = _workspace_fingerprint(workspace)
    second = recover_with_deferred_successor(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint=recovered_fingerprint,
        recovering_run_id="run-recovery-2",
    )

    assert second["status"] == "BLOCKED"
    assert "stale recovery closure" in str(second["reason"])
    assert "predecessor lease" in str(second["reason"])
    assert backup.is_file()
