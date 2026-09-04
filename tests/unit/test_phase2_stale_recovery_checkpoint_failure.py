from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure
from ai_qa_automation.state import StateStore


def _verified_regression_details() -> dict[str, object]:
    suite_id = "sha256:" + "a" * 64
    return {
        "scope": "regression",
        "regression_suite_verified": True,
        "regression_suite_id": suite_id,
        "regression_suite": {
            "suite_id": suite_id,
            "pre_post_collection_match": True,
            "execution_nodes_match": True,
            "node_count": 1,
            "execution_subject_digest": "sha256:" + "b" * 64,
        },
    }


def _closed_revision_checks(path: str) -> list[ValidationResult]:
    return [
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=1,
            status=ValidationStatus.PASS,
            summary="patch safety passed",
            details={"path": path},
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:targeted",
            revision=1,
            status=ValidationStatus.PASS,
            summary="targeted pytest passed",
            details={
                "scope": "targeted",
                "mutation_target_bound": True,
                "mutation_target": path,
            },
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:regression",
            revision=1,
            status=ValidationStatus.PASS,
            summary="regression passed",
            details=_verified_regression_details(),
        ),
    ]


def test_stale_recovery_state_checkpoint_failure_keeps_runtime_pending_after_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    target.write_text("candidate\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    root_stat = workspace.stat(follow_symlinks=False)
    run_root_stat = prior_run.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
        },
        "workspace_fingerprint": "fp-after-mutation",
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": relative_path,
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "change_revision_before": 0,
        },
    }
    runtime_path = prior_run / "runtime.json"
    runtime_path.write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    state_path = prior_run / "state.json"
    prior_state = AgentRunState(
        run_id="run-old",
        objective="state checkpoint failure after stale rollback restore",
        workspace=str(workspace),
        change_revision=1,
        terminal_status=TerminalStatus.SUCCESS,
        files_modified=[relative_path],
        validation_results=_closed_revision_checks(relative_path),
    )
    StateStore(state_path).save(prior_state)
    assert (
        evaluate_revision_closure(
            prior_state.validation_results,
            current_revision=prior_state.change_revision,
        ).closed
        is True
    )

    original_save = StateStore.save

    def fail_prior_state_save(self: StateStore, state: AgentRunState) -> None:
        if self.path == state_path:
            raise OSError("simulated stale recovery state checkpoint failure")
        original_save(self, state)

    monkeypatch.setattr(StateStore, "save", fail_prior_state_save)

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={
            "run_id": "run-old",
            "run_root_identity": {
                "device": run_root_stat.st_dev,
                "inode": run_root_stat.st_ino,
            },
        },
        current_workspace_fingerprint="fp-after-mutation",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "canonical validation lineage could not be durably reconciled" in str(result["reason"])
    assert target.read_bytes() == original
    assert backup.is_file()

    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)

    persisted_state = StateStore(state_path).load()
    assert persisted_state.terminal_status is TerminalStatus.SUCCESS
    assert persisted_state.files_modified == [relative_path]
    assert (
        evaluate_revision_closure(
            persisted_state.validation_results,
            current_revision=persisted_state.change_revision,
        ).closed
        is True
    )

    inspection = inspect_recovery(prior_run)
    assert inspection["recoverable"] is False
    assert "runtime journal authority is invalid" in str(inspection["reason"])
