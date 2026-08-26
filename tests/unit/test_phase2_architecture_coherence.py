from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.internal_tools import RuntimeServices, _change_revision_closed
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RepeatedActionError, RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import pretool_policy_output
from ai_qa_automation.runtime.validation_truth import (
    active_validation_set,
    determine_terminal_outcome,
    evaluate_revision_closure,
)


def validation(
    name: str,
    *,
    status: ValidationStatus = ValidationStatus.PASS,
    gate_id: str | None = None,
    revision: int = 0,
    details: dict[str, Any] | None = None,
) -> ValidationResult:
    return ValidationResult(
        name=name,
        gate_id=gate_id,
        revision=revision,
        status=status,
        summary=f"{name}: {status.value}",
        details=details or {},
    )


def changed_revision_checks(path: str = "tests/test_checkout.py") -> list[ValidationResult]:
    return [
        validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=1,
            details={"path": path},
        ),
        validation(
            "pytest",
            gate_id="pytest:targeted",
            revision=1,
            details={
                "scope": "targeted",
                "mutation_target_bound": True,
                "mutation_target": path,
            },
        ),
        validation(
            "pytest",
            gate_id="pytest:regression",
            revision=1,
            details={"scope": "regression"},
        ),
    ]


def test_unchanged_success_requires_exact_operator_gate_contract() -> None:
    checks = [validation("pytest", gate_id="pytest:full")]

    status, reason = determine_terminal_outcome("success", checks)
    assert status is TerminalStatus.NOT_VERIFIED
    assert "operator did not supply" in reason

    status, _ = determine_terminal_outcome(
        "success",
        checks,
        objective_gate_id="pytest:other",
    )
    assert status is TerminalStatus.NOT_VERIFIED

    status, _ = determine_terminal_outcome(
        "success",
        checks,
        objective_gate_id="pytest:full",
    )
    assert status is TerminalStatus.SUCCESS


def test_objective_contract_cannot_hide_another_active_failure() -> None:
    checks = [
        validation("pytest", gate_id="pytest:full"),
        validation("json_schema", gate_id="json_schema:x", status=ValidationStatus.FAIL),
    ]

    status, reason = determine_terminal_outcome(
        "success",
        checks,
        objective_gate_id="pytest:full",
    )

    assert status is TerminalStatus.FAILURE
    assert "json_schema:x" in reason


def test_same_gate_same_revision_pass_fail_remains_not_verified() -> None:
    checks = [
        validation("pytest", gate_id="pytest:full", status=ValidationStatus.PASS),
        validation("pytest", gate_id="pytest:full", status=ValidationStatus.FAIL),
    ]

    active = active_validation_set(checks)
    assert active.conflicting_gate_ids == ("pytest:full",)

    status, _ = determine_terminal_outcome(
        "success",
        checks,
        objective_gate_id="pytest:full",
    )
    assert status is TerminalStatus.NOT_VERIFIED


def test_changed_revision_requires_one_exact_subject_and_both_pytest_scopes() -> None:
    path = "tests/test_checkout.py"
    checks = changed_revision_checks(path)

    closure = evaluate_revision_closure(checks, current_revision=1, expected_path=path)
    assert closure.closed is True
    assert closure.mutation_path == path

    wrong_subject = evaluate_revision_closure(
        checks,
        current_revision=1,
        expected_path="tests/test_other.py",
    )
    assert wrong_subject.closed is False
    assert wrong_subject.code == "unexpected_patch_subject"

    no_regression = evaluate_revision_closure(checks[:-1], current_revision=1)
    assert no_regression.closed is False
    assert no_regression.code == "incomplete_pytest_closure"


def test_legacy_internal_mutation_precheck_conforms_to_shared_closure(tmp_path: Path) -> None:
    state = AgentRunState(objective="mutation closure", workspace=str(tmp_path), change_revision=1)
    services = RuntimeServices(
        workspace=tmp_path,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=10,
        max_repeated_action=3,
    )

    scenarios = [
        changed_revision_checks(),
        changed_revision_checks()[:-1],
        [
            *changed_revision_checks(),
            validation(
                "pytest",
                gate_id="pytest:failed-extra",
                revision=1,
                status=ValidationStatus.FAIL,
                details={"scope": "targeted"},
            ),
        ],
    ]
    for checks in scenarios:
        state.validation_results = checks
        expected = evaluate_revision_closure(checks, current_revision=1).closed
        assert _change_revision_closed(services.state) is expected


def make_control(tmp_path: Path, *, max_repeated_action: int = 2) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-phase2",
        max_repeated_action=max_repeated_action,
    )


def test_live_repetition_authority_is_content_sensitive_and_persisted(tmp_path: Path) -> None:
    control = make_control(tmp_path, max_repeated_action=2)

    control.register_tool_request("mcp__github__get_issue", "input-a")
    control.register_tool_request("mcp__github__get_issue", "input-a")
    control.register_tool_request("mcp__github__get_issue", "input-b")

    with pytest.raises(RepeatedActionError, match="repeated identical action"):
        control.register_tool_request("mcp__github__get_issue", "input-a")

    snapshot = control.snapshot()
    counts = cast(dict[str, int], snapshot["repeated_action_counts"])
    assert counts["mcp__github__get_issue:input-a"] == 2
    assert counts["mcp__github__get_issue:input-b"] == 1


def test_live_services_mirror_control_count_without_double_charging(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    state = AgentRunState(objective="count all live tool requests", workspace=str(tmp_path / "sut"))
    services = LiveRuntimeServices(
        workspace=tmp_path / "sut",
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=10,
        max_repeated_action=2,
        workspace_root_identity=pin_directory_identity(
            tmp_path / "sut", label="test workspace"
        ),
        control=control,
    )

    control.budget.charge_tool()
    control.register_tool_request("mcp__qa__inspect_repository", "input-a")
    services.consume("inspect_repository", {})
    services.consume("inspect_repository", {})

    assert state.tool_call_count == 1


def test_external_pretool_uses_same_count_and_repetition_authority(tmp_path: Path) -> None:
    control = make_control(tmp_path, max_repeated_action=2)
    state = AgentRunState(objective="read one provider issue", workspace=str(tmp_path / "sut"))
    control_root = tmp_path / "control"
    control_root.mkdir()
    policy = PolicyEngine(control_root, tmp_path / "sut")
    request = {
        "tool_name": "mcp__github__get_issue",
        "tool_input": {"issue_number": 42},
    }

    first = pretool_policy_output(policy, request, state=state, control=control)
    second = pretool_policy_output(policy, request, state=state, control=control)
    third = pretool_policy_output(policy, request, state=state, control=control)

    assert first == {}
    assert second == {}
    assert third["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "runtime-repetition" in third["hookSpecificOutput"]["permissionDecisionReason"]
    assert state.tool_call_count == 3
    assert control.budget.snapshot().tool_calls == 3
    assert control.budget.snapshot().network_calls == 2
    assert len(state.policy_decisions) == 2
