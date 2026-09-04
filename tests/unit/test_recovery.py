from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.state import StateStore


def save_state(run_dir: Path, state: AgentRunState) -> None:
    StateStore(run_dir / "state.json").save(state)


def save_runtime(
    run_dir: Path,
    workspace: Path,
    pending_mutation: object | None = None,
) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    journal_status = RunJournal(run_dir / "journal.jsonl").verify()
    workspace_status = workspace.stat(follow_symlinks=False)
    (run_dir / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(workspace.resolve()),
                "workspace_root_identity": {
                    "device": workspace_status.st_dev,
                    "inode": workspace_status.st_ino,
                },
                "journal_event_count": journal_status["events"],
                "journal_head_hash": journal_status["head_hash"],
                "pending_mutation": pending_mutation,
            }
        ),
        encoding="utf-8",
    )


def base_state(workspace: Path, **updates: object) -> AgentRunState:
    state = AgentRunState(
        run_id="run-1",
        objective="Investigate checkout",
        workspace=str(workspace),
        terminal_status=TerminalStatus.NOT_VERIFIED,
        terminal_reason="persisted for recovery inspection",
    )
    return state.model_copy(update=updates)


def verified_regression_details() -> dict[str, object]:
    suite_id = "sha256:" + "a" * 64
    return {
        "scope": "regression",
        "args": [],
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


def verified_targeted_details(path: str) -> dict[str, object]:
    execution_id = "sha256:" + "c" * 64
    return {
        "scope": "targeted",
        "args": [path],
        "mutation_target": path,
        "mutation_target_bound": True,
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


def closed_revision_validations(path: str = "tests/test_x.py") -> list[ValidationResult]:
    return [
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=1,
            status=ValidationStatus.PASS,
            summary="safe",
            details={"path": path, "scope": "static_patch_safety"},
        ),
        ValidationResult(
            name="pytest",
            gate_id="targeted",
            revision=1,
            status=ValidationStatus.PASS,
            summary="targeted pass",
            details=verified_targeted_details(path),
        ),
        ValidationResult(
            name="pytest",
            gate_id="regression",
            revision=1,
            status=ValidationStatus.PASS,
            summary="regression pass",
            details=verified_regression_details(),
        ),
    ]


def test_revision_zero_is_safe_to_start_new_session_from_persisted_state(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    save_runtime(run_dir, workspace)

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is True
    assert result["run_id"] == "run-1"
    assert result["change_revision"] == 0
    assert result["revision_closed"] is True
    assert result["journal_binding"]["valid"] is True
    assert result["workspace_authority"] == {"valid": True}
    assert result["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"
    assert "does not replay or continue" in result["note"]


def test_changed_revision_requires_exact_bound_targeted_and_regression_passes(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(
        run_dir,
        base_state(
            workspace,
            change_revision=1,
            validation_results=closed_revision_validations(),
        ),
    )
    RunJournal(run_dir / "journal.jsonl").append("validation_closed")
    save_runtime(run_dir, workspace)

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is True
    assert result["revision_closed"] is True
    assert result["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"


def test_unbound_targeted_validation_is_not_recovery_closed(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    validations = closed_revision_validations()
    validations[1] = validations[1].model_copy(
        update={
            "details": {
                "scope": "targeted",
                "args": ["tests/test_other.py"],
                "mutation_target": "tests/test_x.py",
                "mutation_target_bound": False,
            }
        }
    )
    save_state(
        run_dir,
        base_state(workspace, change_revision=1, validation_results=validations),
    )
    RunJournal(run_dir / "journal.jsonl").append("validation_incomplete")
    save_runtime(run_dir, workspace)

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is True
    assert result["revision_closed"] is False
    assert result["resume_policy"] == "manual-review-required-before-new-session"


def test_pending_mutation_forces_manual_review_even_when_gates_pass(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(
        run_dir,
        base_state(
            workspace,
            change_revision=1,
            validation_results=closed_revision_validations(),
        ),
    )
    RunJournal(run_dir / "journal.jsonl").append("mutation_prepared")
    save_runtime(run_dir, workspace, {"relative_path": "tests/test_x.py"})

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is True
    assert result["revision_closed"] is False
    assert result["resume_policy"] == "manual-review-required-before-new-session"


def test_replaced_workspace_root_is_not_recoverable(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    save_runtime(run_dir, workspace)

    original = tmp_path / "sut-original"
    workspace.rename(original)
    workspace.mkdir()

    result = inspect_recovery(run_dir)

    assert result == {
        "recoverable": False,
        "reason": "runtime.json workspace root identity does not match current workspace",
    }


def test_hash_valid_journal_growth_after_runtime_snapshot_is_not_recoverable(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    save_runtime(run_dir, workspace)
    RunJournal(run_dir / "journal.jsonl").append("unexpected_valid_event")

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is False
    assert result["reason"] == (
        "runtime journal authority is invalid: "
        "runtime journal authority does not match persisted journal"
    )


def test_missing_run_directory_is_not_recoverable(tmp_path: Path) -> None:
    result = inspect_recovery(tmp_path / "missing-run")

    assert result == {"recoverable": False, "reason": "run directory is missing"}


def test_missing_state_is_not_recoverable(tmp_path: Path) -> None:
    run_dir = tmp_path / "missing-state"
    run_dir.mkdir()

    result = inspect_recovery(run_dir)

    assert result == {"recoverable": False, "reason": "state.json is missing"}


def test_missing_runtime_is_not_recoverable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")

    result = inspect_recovery(run_dir)

    assert result == {"recoverable": False, "reason": "runtime.json is missing"}


def test_missing_journal_is_not_recoverable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    save_runtime(run_dir, workspace)

    result = inspect_recovery(run_dir)

    assert result == {"recoverable": False, "reason": "journal.jsonl is missing"}


def test_non_object_runtime_is_not_recoverable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    (run_dir / "runtime.json").write_text("[]", encoding="utf-8")

    result = inspect_recovery(run_dir)

    assert result == {"recoverable": False, "reason": "runtime.json root must be an object"}


def test_oversized_runtime_metadata_is_rejected_before_parse(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    runtime_path = run_dir / "runtime.json"
    runtime_path.write_bytes(b"{" + (b"x" * 2_000_001) + b"}")

    result = inspect_recovery(run_dir)

    assert result == {"recoverable": False, "reason": "runtime.json exceeds restore size bound"}


def test_corrupt_journal_is_not_recoverable(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    save_state(run_dir, base_state(workspace))
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    save_runtime(run_dir, workspace)
    (run_dir / "journal.jsonl").write_text('{"seq": 1, "record_hash": "bad"}\n', encoding="utf-8")

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is False
    assert result["reason"].startswith("journal could not be verified:")


def test_recovery_rejects_symlinked_state_control_file(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    outside = tmp_path / "outside-state.json"
    outside.write_text("{}", encoding="utf-8")
    state_path = run_dir / "state.json"
    try:
        state_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is False
    assert "state.json" in result["reason"]
    assert "symlink" in result["reason"]
