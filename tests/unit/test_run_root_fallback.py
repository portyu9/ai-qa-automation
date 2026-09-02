from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.stale_recovery as stale_recovery_module
import ai_qa_automation.state as state_module
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore


def test_unenforceable_run_root_identity_is_not_published_as_lease_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    monkeypatch.setattr(state_module, "descriptor_relative_authority_supported", lambda: False)
    state_store = StateStore(artifact_root / "run-old" / "state.json")
    assert state_store.parent_identity is None

    lease = WorkspaceLease(
        artifact_root,
        workspace,
        "run-old",
        run_root_identity=state_store.parent_identity,
    ).acquire()
    try:
        previous_lease = json.loads(lease.path.read_text(encoding="utf-8"))
    finally:
        lease.release()

    assert previous_lease["run_root_identity"] is None

    monkeypatch.setattr(
        stale_recovery_module,
        "descriptor_relative_authority_supported",
        lambda: False,
    )
    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint="fallback-fingerprint",
        recovering_run_id="run-new",
    )

    assert result == {"status": "NONE", "previous_run_id": "run-old"}
