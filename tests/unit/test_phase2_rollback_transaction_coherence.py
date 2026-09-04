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
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.mutation_lineage import build_rollback_lineage_checkpoints
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.run_control import RuntimeControl
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


def _verified_targeted_details(path: str) -> dict[str, object]:
    execution_id = "sha256:" + "c" * 64
    return {
        "scope": "targeted",
        "mutation_target_bound": True,
        "mutation_target": path,
        "targeted_outcome_report_verified": True,
        "targeted_execution_id": execution_id,
        "targeted_executed_pass_count": 1,
        "targeted_executed_pass_paths": [path],
        "targeted_execution": {
            "execution_id": execution_id,
            "git_sha": "d" * 40,
            "source_fingerprint": "sha256:" + "e" * 64,
            "execution_subject_digest": "sha256:" + "f" * 64,
            "report_complete": True,
            "child_exit_code": 0,
            "pytest_returncode": 0,
            "passed_call_count": 1,
            "passed_paths": [path],
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
            details=_verified_targeted_details(path),
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:regression",
            revision=1,
            status=ValidationStatus.PASS,
            summary="full regression passed",
            details=_verified_regression_details(),
        ),
    ]


def _live_pending_run(
    tmp_path: Path,
) -> tuple[RuntimeControl, StateStore, AgentRunState, Path, Path, str]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    target.write_text("original\n", encoding="utf-8")

    run_dir = tmp_path / "artifacts" / "run-live"
    store = StateStore(run_dir / "state.json")
    state = AgentRunState(
        run_id="run-live",
        objective="rollback transaction coherence",
        workspace=str(workspace),
    )
    store.save(state)
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=10,
            max_mutations=3,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-live",
    )
    before_close, after_close = build_rollback_lineage_checkpoints(state, store)
    control.rollback_lineage_before_close = before_close
    control.rollback_lineage_after_close = after_close
    control.prepare_mutation(relative_path, change_revision_before=0)
    control.persist()
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))

    target.write_text("candidate\n", encoding="utf-8")
    state.change_revision = 1
    state.files_modified = [relative_path]
    state.validation_results = _closed_revision_checks(relative_path)
    state.terminal_status = TerminalStatus.SUCCESS
    state.terminal_reason = "validated candidate"
    store.save(state)
    assert (
        evaluate_revision_closure(
            state.validation_results,
            current_revision=state.change_revision,
        ).closed
        is True
    )
    return control, store, state, target, backup, relative_path


def test_preclose_state_failure_preserves_candidate_and_pending_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, store, state, target, backup, _path = _live_pending_run(tmp_path)

    def fail_save(_state: AgentRunState) -> None:
        raise OSError("simulated state checkpoint failure")

    monkeypatch.setattr(store, "save", fail_save)

    with pytest.raises(OSError, match="state checkpoint failure"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert control.pending_mutation is not None
    assert backup.is_file()
    runtime = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert isinstance(runtime["pending_mutation"], dict)
    persisted = StateStore(store.path).load()
    assert persisted.terminal_status is TerminalStatus.SUCCESS
    assert (
        evaluate_revision_closure(
            persisted.validation_results,
            current_revision=persisted.change_revision,
        ).closed
        is True
    )
    assert state.terminal_status is TerminalStatus.NOT_VERIFIED


def test_postclose_state_failure_retains_persisted_not_verified_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, store, _state, target, backup, relative_path = _live_pending_run(tmp_path)
    original_save = store.save
    save_calls = 0

    def fail_second_save(state: AgentRunState) -> None:
        nonlocal save_calls
        save_calls += 1
        if save_calls == 2:
            raise OSError("simulated post-close state checkpoint failure")
        original_save(state)

    monkeypatch.setattr(store, "save", fail_second_save)

    with pytest.raises(OSError, match="post-close state checkpoint failure"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "original\n"
    assert control.pending_mutation is None
    assert backup.is_file()
    runtime = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert runtime["pending_mutation"] is None

    persisted = StateStore(store.path).load()
    assert persisted.terminal_status is TerminalStatus.NOT_VERIFIED
    assert persisted.files_modified == [relative_path]
    rollback_gate = persisted.validation_results[-1]
    assert rollback_gate.gate_id == f"mutation_transaction:{relative_path}"
    assert rollback_gate.status is ValidationStatus.NOT_VERIFIED
    assert rollback_gate.details["scope"] == "rollback_pending"
    closure = evaluate_revision_closure(
        persisted.validation_results,
        current_revision=persisted.change_revision,
    )
    assert closure.closed is False
    assert closure.code == "incomplete_revision_validation"
    inspection = inspect_recovery(control.metadata_path.parent)
    assert inspection["recoverable"] is True
    assert inspection["revision_closed"] is False


def test_live_rollback_rejects_impossible_revision_gap_before_target_write(tmp_path: Path) -> None:
    control, store, state, target, backup, _relative_path = _live_pending_run(tmp_path)
    state.change_revision = 2
    store.save(state)

    with pytest.raises(RuntimeError, match="revision lineage is incoherent"):
        control.rollback_pending_mutation(reason="incoherent revision")

    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert control.pending_mutation is not None
    assert backup.is_file()
    runtime = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert isinstance(runtime["pending_mutation"], dict)


def test_stale_recovery_rejects_impossible_revision_gap_before_target_write(
    tmp_path: Path,
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
    prior_status = prior_run.stat(follow_symlinks=False)
    prior_lease = {
        "run_id": "run-old",
        "run_root_identity": {"device": prior_status.st_dev, "inode": prior_status.st_ino},
    }
    original = b"original\n"
    backup.write_bytes(original)
    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    status = workspace.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {"device": status.st_dev, "inode": status.st_ino},
        "workspace_fingerprint": "fp",
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
    (prior_run / "runtime.json").write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    StateStore(prior_run / "state.json").save(
        AgentRunState(
            run_id="run-old",
            objective="impossible stale revision gap",
            workspace=str(workspace),
            change_revision=2,
            files_modified=[relative_path, "tests/test_other.py"],
        )
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=prior_lease,
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "more than one revision ahead" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert backup.is_file()
    persisted_runtime = json.loads((prior_run / "runtime.json").read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)
