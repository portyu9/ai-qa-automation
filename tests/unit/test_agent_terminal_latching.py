from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.agent as agent_module
import ai_qa_automation.runtime.runtime_hooks as runtime_hooks_module
from ai_qa_automation.agent import (
    _enforce_terminal_workspace_freshness,
    _may_recompute_terminal_outcome,
)
from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_policy_output
from ai_qa_automation.runtime.validation_truth import determine_terminal_outcome
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)

_TERMINAL_RECOMPUTE_CONTRACT: dict[TerminalStatus | None, bool] = {
    None: True,
    TerminalStatus.SUCCESS: True,
    TerminalStatus.FAILURE: False,
    TerminalStatus.BLOCKED: False,
    TerminalStatus.INSUFFICIENT_EVIDENCE: False,
    TerminalStatus.POLICY_DENIED: False,
    TerminalStatus.INFRASTRUCTURE_FAILURE: False,
    TerminalStatus.CANCELLED: False,
    TerminalStatus.BUDGET_EXCEEDED: False,
    TerminalStatus.NOT_VERIFIED: False,
}


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=5,
            max_mutations=2,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="terminal-latching-test",
    )
    control.set_workspace_fingerprint("sha256:authorized")
    return control


def _objective_pass(state: AgentRunState, gate_id: str) -> None:
    state.validation_results.append(
        ValidationResult(
            name="pytest",
            gate_id=gate_id,
            revision=0,
            status=ValidationStatus.PASS,
            summary="Objective-bound deterministic validation passed.",
        )
    )


def _subject_unavailable(*_args: object, **_kwargs: object) -> WorkspaceFreshness:
    return WorkspaceFreshness(
        WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE,
        "Workspace subject identity could not be revalidated safely.",
    )


def test_terminal_recompute_contract_is_exhaustive_and_review_forcing() -> None:
    assert set(_TERMINAL_RECOMPUTE_CONTRACT) == {None} | set(TerminalStatus)


@pytest.mark.parametrize(
    ("status", "expected"),
    list(_TERMINAL_RECOMPUTE_CONTRACT.items()),
    ids=lambda value: "unset" if value is None else getattr(value, "value", str(value)),
)
def test_terminal_recompute_contract(
    status: TerminalStatus | None,
    expected: bool,
) -> None:
    assert _may_recompute_terminal_outcome(status) is expected


def test_posttool_subject_unavailable_latches_over_prior_objective_pass_and_later_freshness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    objective_gate = "pytest:objective"
    state = AgentRunState(
        objective="prove terminal freshness",
        objective_gate_id=objective_gate,
        workspace=str(control.workspace),
    )
    _objective_pass(state, objective_gate)
    monkeypatch.setattr(
        runtime_hooks_module,
        "observe_workspace_freshness",
        _subject_unavailable,
    )

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__classify_failure",
            "tool_input": {},
            "tool_response": {"content": [{"type": "text", "text": "advisory result"}]},
        },
        state=state,
        control=control,
    )

    assert result["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True
    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert state.terminal_reason == ("Workspace subject identity could not be revalidated safely.")

    candidate_status, _candidate_reason = determine_terminal_outcome(
        "success",
        state.validation_results,
        current_revision=0,
        objective_gate_id=objective_gate,
    )
    assert candidate_status is TerminalStatus.SUCCESS
    assert _may_recompute_terminal_outcome(state.terminal_status) is False

    monkeypatch.setattr(
        agent_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.FRESH,
            "Current workspace fingerprint matches the authorized runtime baseline.",
        ),
    )
    _enforce_terminal_workspace_freshness(state, control, control.workspace)

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert state.terminal_reason == ("Workspace subject identity could not be revalidated safely.")


def test_validation_posttool_subject_unavailable_latches_and_poisons_lineage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    state = AgentRunState(
        objective="validate exact target",
        workspace=str(control.workspace),
    )
    monkeypatch.setattr(
        runtime_hooks_module,
        "observe_workspace_freshness",
        _subject_unavailable,
    )

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {"args": []},
            "tool_response": {"content": [{"type": "text", "text": "passed"}]},
        },
        state=state,
        control=control,
    )

    assert result["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True
    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert len(state.validation_results) == 1
    freshness = state.validation_results[0]
    assert freshness.name == "workspace_freshness"
    assert freshness.status is ValidationStatus.NOT_VERIFIED
    assert freshness.revision == 0
    assert freshness.details["scope"] == "post_execution_workspace_drift"
    assert freshness.details["tool_name"] == "mcp__qa__run_pytest"
    assert _may_recompute_terminal_outcome(state.terminal_status) is False
