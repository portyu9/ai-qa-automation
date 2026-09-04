from __future__ import annotations

from pathlib import Path

from ai_qa_automation.models import AgentRunState, ValidationResult, ValidationStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_policy_output
from ai_qa_automation.tools.repository import RepositoryInspector


def control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-binding"
    subject = RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-binding",
    )
    subject.set_workspace_fingerprint(RepositoryInspector(subject.workspace).snapshot().fingerprint)
    return subject


def patch_safety(path: str) -> ValidationResult:
    return ValidationResult(
        name="test_patch_safety",
        gate_id=f"test_patch_safety:{path}",
        revision=1,
        status=ValidationStatus.PASS,
        summary="safe",
        details={"path": path, "scope": "static_patch_safety"},
    )


def verified_regression_details() -> dict[str, object]:
    suite_id = "sha256:" + "a" * 64
    return {
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


def pytest_result(*, scope: str, args: list[str]) -> ValidationResult:
    details: dict[str, object] = {"scope": scope, "args": args}
    if scope == "regression":
        details.update(verified_regression_details())
    return ValidationResult(
        name="pytest",
        gate_id=f"pytest:{scope}:{'|'.join(args)}",
        revision=1,
        status=ValidationStatus.PASS,
        summary="pytest passed",
        details=details,
    )


def successful_pytest_hook(state: AgentRunState, subject: RuntimeControl) -> None:
    posttool_policy_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {},
            "tool_response": {"content": [{"type": "text", "text": "pass"}]},
        },
        state=state,
        control=subject,
    )


def test_unrelated_targeted_pytest_is_diagnostic_and_cannot_close_mutation(
    tmp_path: Path,
) -> None:
    subject = control(tmp_path)
    changed = "tests/test_changed.py"
    subject.prepare_mutation(changed)
    state = AgentRunState(objective="repair", workspace=str(subject.workspace), change_revision=1)
    state.validation_results.append(patch_safety(changed))
    state.validation_results.append(
        pytest_result(scope="targeted", args=["tests/test_unrelated.py::test_other"])
    )

    successful_pytest_hook(state, subject)

    targeted = state.validation_results[-1]
    assert targeted.details["scope"] == "diagnostic"
    assert targeted.details["mutation_target"] == changed
    assert targeted.details["mutation_target_bound"] is False
    assert subject.pending_mutation is not None

    state.validation_results.append(pytest_result(scope="regression", args=[]))
    successful_pytest_hook(state, subject)
    assert subject.pending_mutation is not None


def test_exact_pending_file_target_plus_regression_closes_mutation(tmp_path: Path) -> None:
    subject = control(tmp_path)
    changed = "tests/test_changed.py"
    subject.prepare_mutation(changed)
    state = AgentRunState(objective="repair", workspace=str(subject.workspace), change_revision=1)
    state.validation_results.append(patch_safety(changed))
    state.validation_results.append(
        pytest_result(scope="targeted", args=[f"{changed}::test_changed_behavior"])
    )

    successful_pytest_hook(state, subject)
    targeted = state.validation_results[-1]
    assert targeted.details["scope"] == "targeted"
    assert targeted.details["mutation_target_bound"] is True
    assert subject.pending_mutation is not None

    state.validation_results.append(pytest_result(scope="regression", args=[]))
    successful_pytest_hook(state, subject)
    assert subject.pending_mutation is None
