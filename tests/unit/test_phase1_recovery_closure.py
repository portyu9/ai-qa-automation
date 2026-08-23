from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.stale_recovery as stale_recovery_module
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation


def test_failed_stale_recovery_close_retains_authority_but_requires_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    runtime_path = prior_run / "runtime.json"
    runtime_payload = {
        "workspace": str(workspace.resolve()),
        "workspace_fingerprint": "fp-after-mutation",
        "journal_event_count": 0,
        "pending_mutation": {
            "relative_path": "tests/test_checkout.py",
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
        },
    }
    runtime_path.write_text(json.dumps(runtime_payload), encoding="utf-8")

    def fail_runtime_close(_path: Path, _payload: dict[str, object]) -> None:
        raise OSError("simulated durable metadata failure")

    with monkeypatch.context() as patch:
        patch.setattr(stale_recovery_module, "atomic_write_json", fail_runtime_close)
        first = recover_stale_mutation(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease={"run_id": "run-old"},
            current_workspace_fingerprint="fp-after-mutation",
            recovering_run_id="run-new",
        )

    assert first["status"] == "BLOCKED"
    assert "manual reconciliation" in str(first["reason"])
    assert target.read_bytes() == original
    assert backup.read_bytes() == original
    persisted = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert persisted["pending_mutation"] is not None

    second = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp-after-restore",
        recovering_run_id="run-next",
    )

    assert second["status"] == "BLOCKED"
    assert "overwriting newer work" in str(second["reason"])
    assert target.read_bytes() == original
    assert backup.read_bytes() == original
