from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationResult, ValidationStatus
from ai_qa_automation.runtime.validation_truth import determine_terminal_outcome, evaluate_revision_closure


def _passing_gate() -> ValidationResult:
    return ValidationResult(
        name="pytest",
        gate_id="pytest:full",
        revision=0,
        status=ValidationStatus.PASS,
        summary="full pytest passed",
    )


def test_agent_run_state_rejects_negative_runtime_counters(tmp_path: Path) -> None:
    for field in (
        "iteration",
        "change_revision",
        "tool_call_count",
        "retry_count",
        "token_usage",
        "cost",
        "duration",
    ):
        value: int | float = -0.1 if field in {"cost", "duration"} else -1
        with pytest.raises(ValidationError, match=field):
            AgentRunState(
                objective="invalid counter must fail closed",
                workspace=str(tmp_path),
                **{field: value},
            )


def test_negative_revision_never_closes_or_promotes_terminal_success() -> None:
    closure = evaluate_revision_closure([_passing_gate()], current_revision=-1)
    assert closure.closed is False
    assert closure.code == "invalid_revision"

    status, reason = determine_terminal_outcome(
        "success",
        [_passing_gate()],
        current_revision=-1,
        objective_gate_id="pytest:full",
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "revision is invalid" in reason.lower()
