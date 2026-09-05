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


def write_runtime(
    path: Path,
    payload: dict[str, object],
    *,
    bind_journal: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = dict(payload)
    pending = rendered.get("pending_mutation")
    if isinstance(pending, dict) and pending:
        normalized_pending = dict(pending)
        normalized_pending.setdefault("change_revision_before", 0)
        rendered["pending_mutation"] = normalized_pending
        pending = normalized_pending
    if bind_journal and isinstance(pending, dict) and pending:
        journal = RunJournal(path.parent / "journal.jsonl")
        if journal.event_count == 0:
            journal.append("mutation_prepared")
        rendered["journal_event_count"] = journal.event_count
        rendered["journal_head_hash"] = journal.head_hash
    path.write_text(json.dumps(rendered, indent=2, sort_keys=True), encoding="utf-8")
    if isinstance(pending, dict) and pending:
        workspace = rendered.get("workspace")
        if isinstance(workspace, str):
            StateStore(path.parent / "state.json").save(
                AgentRunState(
                    run_id=path.parent.name,
                    objective="stale recovery fixture",
                    workspace=workspace,
                )
            )


def stale_runtime_payload(
    workspace: Path,
    *,
    relative_path: str,
    existed: bool,
    backup_path: str | None = None,
    original_sha256: str | None = None,
    fingerprint: str = "fp",
) -> dict[str, object]:
    status = workspace.stat(follow_symlinks=False)
    return {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {"device": status.st_dev, "inode": status.st_ino},
        "workspace_fingerprint": fingerprint,
        "journal_event_count": 0,
        "journal_head_hash": None,
        "pending_mutation": {
            "relative_path": relative_path,
            "existed": existed,
            "backup_path": backup_path,
            "original_sha256": original_sha256,
            "change_revision_before": 0,
        },
    }


def recover(artifact_root: Path, workspace: Path, *, fingerprint: str = "fp") -> dict[str, object]:
    prior_run = artifact_root / "run-old"
    status = prior_run.stat(follow_symlinks=False)
    return recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={
            "run_id": "run-old",
            "run_root_identity": {"device": status.st_dev, "inode": status.st_ino},
        },
        current_workspace_fingerprint=fingerprint,
        recovering_run_id="run-new",
    )


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
        "targeted_execution_authority": "trusted_out_of_process_observer_v1",
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


def test_stale_existing_file_mutation_is_restored_when_fingerprint_matches(tmp_path: Path) -> None:
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
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
            fingerprint="fp-after-mutation",
        ),
    )

    result = recover(artifact_root, workspace, fingerprint="fp-after-mutation")

    assert result == {
        "status": "RECOVERED",
        "previous_run_id": "run-old",
        "path": "tests/test_checkout.py",
    }
    assert target.read_bytes() == original
    assert not backup.exists()
    metadata = json.loads((prior_run / "runtime.json").read_text(encoding="utf-8"))
    assert metadata["pending_mutation"] is None
    assert metadata["recovered_by_run_id"] == "run-new"
    assert metadata["recovered_at"]
    journal = RunJournal(prior_run / "journal.jsonl")
    assert metadata["journal_event_count"] == journal.event_count
    assert metadata["journal_head_hash"] == journal.head_hash


def test_stale_recovery_invalidates_prior_closed_revision_and_success(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path=relative_path,
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
            fingerprint="fp-after-mutation",
        ),
    )
    prior_state = AgentRunState(
        run_id="run-old",
        objective="crashed validated mutation",
        workspace=str(workspace),
        change_revision=1,
        terminal_status=TerminalStatus.SUCCESS,
        files_modified=[relative_path],
        validation_results=_closed_revision_checks(relative_path),
    )
    StateStore(prior_run / "state.json").save(prior_state)
    assert (
        evaluate_revision_closure(
            prior_state.validation_results,
            current_revision=prior_state.change_revision,
        ).closed
        is True
    )

    result = recover(artifact_root, workspace, fingerprint="fp-after-mutation")

    assert result["status"] == "RECOVERED"
    assert target.read_bytes() == original
    recovered_state = StateStore(prior_run / "state.json").load()
    assert recovered_state.change_revision == 1
    assert recovered_state.files_modified == []
    assert recovered_state.terminal_status is TerminalStatus.NOT_VERIFIED
    rollback_gate = recovered_state.validation_results[-1]
    assert rollback_gate.gate_id == f"mutation_transaction:{relative_path}"
    assert rollback_gate.revision == 1
    assert rollback_gate.status is ValidationStatus.NOT_VERIFIED
    closure = evaluate_revision_closure(
        recovered_state.validation_results,
        current_revision=recovered_state.change_revision,
    )
    assert closure.closed is False
    assert closure.code == "incomplete_revision_validation"
    inspection = inspect_recovery(prior_run)
    assert inspection["recoverable"] is True
    assert inspection["revision_closed"] is False
    assert inspection["resume_policy"] == "manual-review-required-before-new-session"


def test_operator_edit_after_crash_blocks_automatic_rollback(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("human edit\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
            fingerprint="old-fingerprint",
        ),
    )

    result = recover(artifact_root, workspace, fingerprint="new-human-fingerprint")

    assert result["status"] == "BLOCKED"
    assert "overwriting newer work" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "human edit\n"
    assert backup.exists()


def test_stale_unverified_new_file_is_removed(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "RECOVERED"
    assert not target.exists()


def test_hash_valid_journal_mismatch_blocks_before_stale_rollback(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
    )
    RunJournal(prior_run / "journal.jsonl").append("unexpected_valid_event")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "runtime journal authority does not match persisted journal" in str(result["reason"])
    assert target.exists()


def test_stale_recovery_rejects_symlinked_target_alias(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    actual = workspace / "actual-tests"
    actual.mkdir()
    target = actual / "test_checkout.py"
    target.write_text("mutated\n", encoding="utf-8")
    alias = workspace / "tests"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "symlink" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_stale_recovery_rejects_symlinked_rollback_backup(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    rollback = prior_run / "rollback"
    rollback.mkdir(parents=True)
    original = b"original\n"
    actual_backup = rollback / "actual.bin"
    actual_backup.write_bytes(original)
    alias = rollback / "checkout.bin"
    try:
        alias.symlink_to(actual_backup)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(alias.absolute()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "symlink" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert actual_backup.exists()


def test_stale_recovery_rejects_symlinked_rollback_directory(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    outside_rollback = tmp_path / "outside-rollback"
    outside_rollback.mkdir()
    original = b"original\n"
    backup = outside_rollback / "checkout.bin"
    backup.write_bytes(original)
    rollback_alias = prior_run / "rollback"
    try:
        rollback_alias.symlink_to(outside_rollback, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "rollback directory" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_stale_recovery_rejects_symlinked_journal_before_mutation(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
        bind_journal=False,
    )
    outside_journal = tmp_path / "outside-journal.jsonl"
    outside_journal.write_text("do not touch\n", encoding="utf-8")
    journal_alias = prior_run / "journal.jsonl"
    try:
        journal_alias.symlink_to(outside_journal)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "run journal" in str(result["reason"])
    assert target.exists()
    assert outside_journal.read_text(encoding="utf-8") == "do not touch\n"


def test_previous_run_id_traversal_is_blocked(tmp_path: Path) -> None:
    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=tmp_path / "sut",
        previous_lease={"run_id": "../escape"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )
    assert result["status"] == "BLOCKED"
    assert "escapes trusted root" in str(result["reason"])


def test_oversized_runtime_metadata_is_blocked_before_json_ingestion(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    runtime = artifact_root / "run-old" / "runtime.json"
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b"{" + (b" " * 2_000_001) + b"}")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "ingestion limit" in str(result["reason"])


def test_non_object_runtime_metadata_is_blocked(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    runtime = artifact_root / "run-old" / "runtime.json"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("[]", encoding="utf-8")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "root must be an object" in str(result["reason"])


def test_invalid_pending_metadata_is_blocked_not_treated_as_noop(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    write_runtime(
        artifact_root / "run-old" / "runtime.json",
        {
            "workspace": str(workspace.resolve()),
            "workspace_fingerprint": "fp",
            "pending_mutation": "tests/test_x.py",
        },
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "pending mutation metadata is invalid" in str(result["reason"])


def test_oversized_rollback_backup_is_blocked_before_read(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")
    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"x" * 2_000_001)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(b"original").hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "2 MB" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_no_previous_lease_is_noop(tmp_path: Path) -> None:
    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=tmp_path / "sut",
        previous_lease=None,
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result == {"status": "NONE"}
