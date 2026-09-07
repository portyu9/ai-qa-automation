from __future__ import annotations

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
from ai_qa_automation.runtime.regression_execution_observer import (
    TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
    build_regression_execution_observation,
)
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_policy_output
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector


def make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-closure-durability"
    control = RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-closure-durability",
    )
    control.set_workspace_fingerprint(RepositoryInspector(control.workspace).snapshot().fingerprint)
    return control


def patch_safety(path: str) -> ValidationResult:
    return ValidationResult(
        name="test_patch_safety",
        gate_id=f"test_patch_safety:{path}",
        revision=1,
        status=ValidationStatus.PASS,
        summary="safe",
        details={"path": path, "scope": "static_patch_safety"},
    )


def targeted_pytest(path: str, *, run_id: str) -> ValidationResult:
    args = [f"{path}::test_changed_behavior"]
    observer_backend = "controller-observer-test-double"
    observer_identity = "sha256:" + "1" * 64
    git_sha = "2" * 40
    source_fingerprint = "sha256:" + "3" * 64
    subject_digest = "sha256:" + "4" * 64
    observation = build_targeted_execution_observation(
        run_id=run_id,
        change_revision=1,
        mutation_path=path,
        pytest_args=tuple(args),
        observer_backend=observer_backend,
        observer_identity=observer_identity,
        git_sha=git_sha,
        source_fingerprint=source_fingerprint,
        execution_subject_digest=subject_digest,
        report_complete=True,
        child_exit_code=0,
        pytest_returncode=0,
        call_report_count=1,
        passed_call_count=1,
        skipped_call_count=0,
        xfail_call_count=0,
        failed_call_count=0,
        passed_paths=(path,),
        report_sha256="sha256:" + "5" * 64,
    )
    return ValidationResult(
        name="pytest",
        gate_id=f"pytest:targeted:{path}",
        revision=1,
        status=ValidationStatus.PASS,
        summary="targeted pytest passed",
        details={
            "scope": "targeted",
            "args": args,
            "targeted_execution_authority": TRUSTED_TARGETED_EXECUTION_AUTHORITY,
            "targeted_outcome_report_verified": True,
            "targeted_observer_backend": observer_backend,
            "targeted_observer_identity": observer_identity,
            "targeted_execution_subject": {
                "git_sha": git_sha,
                "source_fingerprint": source_fingerprint,
                "digest": subject_digest,
                "file_count": 1,
                "total_bytes": 1,
                "ignored_inputs_excluded": True,
                "git_metadata_excluded": True,
            },
            "targeted_execution_id": observation.execution_id,
            "targeted_executed_pass_count": 1,
            "targeted_executed_pass_paths": [path],
            "targeted_execution": observation.model_dump(mode="json"),
        },
    )


def regression_pytest(*, run_id: str) -> ValidationResult:
    args: list[str] = []
    observer_backend = "controller-observer-test-double"
    observer_identity = "sha256:" + "6" * 64
    git_sha = "7" * 40
    source_fingerprint = "sha256:" + "8" * 64
    subject_digest = "sha256:" + "9" * 64
    suite_id = "sha256:" + "a" * 64
    nodeids_sha256 = "b" * 64
    observation = build_regression_execution_observation(
        run_id=run_id,
        change_revision=1,
        pytest_args=tuple(args),
        observer_backend=observer_backend,
        observer_identity=observer_identity,
        git_sha=git_sha,
        source_fingerprint=source_fingerprint,
        execution_subject_digest=subject_digest,
        regression_suite_id=suite_id,
        node_count=1,
        nodeids_sha256="sha256:" + nodeids_sha256,
        collection_complete=True,
        execution_complete=True,
        report_complete=True,
        child_exit_code=0,
        pytest_returncode=0,
        observed_item_count=1,
        passed_item_count=1,
        skipped_item_count=0,
        xfail_item_count=0,
        xpass_item_count=0,
        failed_item_count=0,
        observed_nodeids_sha256="sha256:" + nodeids_sha256,
        report_sha256="sha256:" + "c" * 64,
    )
    return ValidationResult(
        name="pytest",
        gate_id="pytest:regression:full",
        revision=1,
        status=ValidationStatus.PASS,
        summary="regression pytest passed",
        details={
            "scope": "regression",
            "args": args,
            "regression_execution_authority": TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
            "regression_outcome_report_verified": True,
            "regression_observer_backend": observer_backend,
            "regression_observer_identity": observer_identity,
            "regression_suite_id": suite_id,
            "regression_suite": {
                "suite_id": suite_id,
                "git_sha": git_sha,
                "source_fingerprint": source_fingerprint,
                "execution_subject_digest": subject_digest,
                "node_count": 1,
                "nodeids_sha256": nodeids_sha256,
                "execution_root": ".",
                "testpaths_bypassed_by_explicit_root": True,
                "pre_post_collection_match": True,
                "execution_nodes_match": True,
            },
            "regression_execution_id": observation.execution_id,
            "regression_execution": observation.model_dump(mode="json"),
        },
    )


def successful_pytest_hook(
    state: AgentRunState,
    control: RuntimeControl,
    *,
    state_store: StateStore | None = None,
) -> dict[str, object]:
    return posttool_policy_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {},
            "tool_response": {"content": [{"type": "text", "text": "pass"}]},
        },
        state=state,
        state_store=state_store,
        control=control,
    )


def prepare_candidate(
    tmp_path: Path,
) -> tuple[RuntimeControl, AgentRunState, str]:
    control = make_control(tmp_path)
    changed = "tests/test_changed.py"
    control.prepare_mutation(changed, change_revision_before=0)
    target = control.workspace / changed
    target.parent.mkdir(parents=True)
    target.write_text("candidate\n", encoding="utf-8")
    control.set_workspace_fingerprint(RepositoryInspector(control.workspace).snapshot().fingerprint)
    state = AgentRunState(
        objective="repair",
        workspace=str(control.workspace),
        change_revision=1,
    )
    state.validation_results.append(patch_safety(changed))
    state.validation_results.append(targeted_pytest(changed, run_id=state.run_id))
    return control, state, changed


def test_closed_mutation_without_state_store_preserves_pending_authority(tmp_path: Path) -> None:
    control, state, changed = prepare_candidate(tmp_path)

    successful_pytest_hook(state, control)
    assert state.validation_results[-1].details["mutation_target_bound"] is True
    state.validation_results.append(regression_pytest(run_id=state.run_id))

    result = successful_pytest_hook(state, control)

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert control.pending_mutation is not None
    assert control.pending_mutation.relative_path == changed
    assert (control.workspace / changed).read_text(encoding="utf-8") == "candidate\n"
    hook = result["hookSpecificOutput"]
    assert isinstance(hook, dict)
    updated = hook["updatedToolOutput"]
    assert isinstance(updated, dict)
    assert updated["is_error"] is True
    metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pending_mutation"]["relative_path"] == changed


def test_commit_attempt_observes_durable_closed_state_before_pending_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, state, changed = prepare_candidate(tmp_path)
    state_store = StateStore(control.metadata_path.parent / "state.json")
    state_store.save(state)

    successful_pytest_hook(state, control, state_store=state_store)
    assert state.validation_results[-1].details["mutation_target_bound"] is True
    state.validation_results.append(regression_pytest(run_id=state.run_id))

    def interrupted_commit() -> str | None:
        persisted = state_store.load()
        closure = evaluate_revision_closure(
            persisted.validation_results,
            current_revision=persisted.change_revision,
            expected_path=changed,
            expected_run_id=persisted.run_id,
        )
        assert closure.closed is True
        metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
        assert metadata["pending_mutation"]["relative_path"] == changed
        assert control.pending_mutation is not None
        raise OSError("simulated commit interruption")

    monkeypatch.setattr(control, "commit_pending_mutation", interrupted_commit)

    with pytest.raises(OSError, match="simulated commit interruption"):
        successful_pytest_hook(state, control, state_store=state_store)

    assert control.pending_mutation is not None
    persisted = state_store.load()
    closure = evaluate_revision_closure(
        persisted.validation_results,
        current_revision=persisted.change_revision,
        expected_path=changed,
        expected_run_id=persisted.run_id,
    )
    assert closure.closed is True
