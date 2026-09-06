from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import _rollback_unresolved_mutation
from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.run_control import PendingMutation
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure

_RUN_ID = "run-rollback-reporting"
_OBSERVER_BACKEND = "controller-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64


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


def _verified_targeted_details(path: str, *, run_id: str) -> dict[str, object]:
    observer = build_targeted_execution_observation(
        run_id=run_id,
        change_revision=1,
        mutation_path=path,
        pytest_args=(path,),
        observer_backend=_OBSERVER_BACKEND,
        observer_identity=_OBSERVER_IDENTITY,
        git_sha=_GIT_SHA,
        source_fingerprint=_SOURCE_FINGERPRINT,
        execution_subject_digest=_SUBJECT_DIGEST,
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
    return {
        "scope": "targeted",
        "args": [path],
        "mutation_target_bound": True,
        "mutation_target": path,
        "targeted_execution_authority": TRUSTED_TARGETED_EXECUTION_AUTHORITY,
        "targeted_outcome_report_verified": True,
        "targeted_observer_backend": _OBSERVER_BACKEND,
        "targeted_observer_identity": _OBSERVER_IDENTITY,
        "targeted_execution_subject": {
            "git_sha": _GIT_SHA,
            "source_fingerprint": _SOURCE_FINGERPRINT,
            "digest": _SUBJECT_DIGEST,
            "file_count": 1,
            "total_bytes": 1,
            "ignored_inputs_excluded": True,
            "git_metadata_excluded": True,
        },
        "targeted_execution_id": observer.execution_id,
        "targeted_executed_pass_count": 1,
        "targeted_executed_pass_paths": [path],
        "targeted_execution": observer.model_dump(mode="json"),
    }


def _closed_revision_checks(path: str, *, run_id: str) -> list[ValidationResult]:
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
            details=_verified_targeted_details(path, run_id=run_id),
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


def test_terminal_rollback_poison_closed_revision_lineage(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = "tests/test_checkout.py"
    pending = PendingMutation(
        relative_path=path,
        existed=False,
        backup_path=None,
        original_sha256=None,
        change_revision_before=0,
    )
    state = AgentRunState(
        run_id=_RUN_ID,
        objective="repair",
        workspace=str(tmp_path),
        change_revision=1,
        terminal_status=TerminalStatus.SUCCESS,
        files_modified=[path],
        validation_results=_closed_revision_checks(path, run_id=_RUN_ID),
    )
    assert (
        evaluate_revision_closure(
            state.validation_results,
            current_revision=1,
            expected_run_id=state.run_id,
        ).closed
        is True
    )

    class FakeControl:
        def __init__(self) -> None:
            self.pending_mutation: PendingMutation | None = pending
            self.workspace_fingerprint: str | None = None

        def rollback_pending_mutation(self, *, reason: str) -> str:
            assert reason == "run ended with an unresolved mutation transaction"
            self.pending_mutation = None
            return path

        def set_workspace_fingerprint(self, fingerprint: str) -> None:
            self.workspace_fingerprint = fingerprint

    class FakeInspector:
        def __init__(self, workspace: Path) -> None:
            assert workspace == tmp_path

        def snapshot(self) -> SimpleNamespace:
            return SimpleNamespace(fingerprint="sha256:restored")

    control = FakeControl()
    monkeypatch.setattr(agent_module, "RepositoryInspector", FakeInspector)

    _rollback_unresolved_mutation(state, control, tmp_path)  # type: ignore[arg-type]

    assert state.terminal_status is TerminalStatus.NOT_VERIFIED
    assert control.pending_mutation is None
    assert control.workspace_fingerprint == "sha256:restored"
    assert state.files_modified == []
    assert state.change_revision == 1
    rollback_gate = state.validation_results[-1]
    assert rollback_gate.gate_id == f"mutation_transaction:{path}"
    assert rollback_gate.revision == 1
    assert rollback_gate.status is ValidationStatus.NOT_VERIFIED
    closure = evaluate_revision_closure(
        state.validation_results,
        current_revision=1,
        expected_run_id=state.run_id,
    )
    assert closure.closed is False
    assert closure.code == "incomplete_revision_validation"
