from __future__ import annotations

import json
from pathlib import Path

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import pretool_policy_output
from ai_qa_automation.runtime.tool_input_bounds import (
    MAX_TOOL_INPUT_UTF8_BYTES,
    MAX_TOOL_NAME_UTF8_BYTES,
)


class _ExplosiveToolName:
    def __str__(self) -> str:
        raise AssertionError("unvalidated tool name was stringified")


def _make_control(tmp_path: Path, *, max_tool_calls: int = 5) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir(exist_ok=True)
    run_dir = tmp_path / "artifacts" / "run"
    return RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=max_tool_calls,
            max_network_calls=5,
            max_mutations=2,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="tool-name-boundary-test",
    )


def _journal_records(control: RuntimeControl) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in control.journal.path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_invalid_tool_name_is_not_stringified_or_persisted(tmp_path: Path) -> None:
    control = _make_control(tmp_path)
    state = AgentRunState(objective="reject invalid tool name", workspace=str(control.workspace))
    result = pretool_policy_output(
        PolicyEngine(tmp_path, control.workspace),
        {"tool_name": _ExplosiveToolName(), "tool_input": {}},
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert "tool name must be a string" in hook["permissionDecisionReason"]
    assert control.budget.snapshot().tool_calls == 1
    record = _journal_records(control)[-1]
    assert record["event"] == "tool_input_denied"
    payload = record["payload"]
    assert isinstance(payload, dict)
    assert payload == {"reason_code": "tool_name_type"}


def test_oversized_tool_name_is_not_persisted_raw(tmp_path: Path) -> None:
    control = _make_control(tmp_path)
    state = AgentRunState(objective="reject oversized tool name", workspace=str(control.workspace))
    oversized = "sensitive-name-" + ("x" * (MAX_TOOL_NAME_UTF8_BYTES + 1000))
    result = pretool_policy_output(
        PolicyEngine(tmp_path, control.workspace),
        {"tool_name": oversized, "tool_input": {}},
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert "tool name exceeds" in hook["permissionDecisionReason"]
    rendered = control.journal.path.read_text(encoding="utf-8")
    assert "sensitive-name-" not in rendered
    record = _journal_records(control)[-1]
    payload = record["payload"]
    assert isinstance(payload, dict)
    assert payload == {"reason_code": "utf8_bytes"}


def test_exhausted_budget_does_not_inspect_unvalidated_tool_name(tmp_path: Path) -> None:
    control = _make_control(tmp_path, max_tool_calls=1)
    state = AgentRunState(
        objective="budget before untrusted metadata",
        workspace=str(control.workspace),
    )
    policy = PolicyEngine(tmp_path, control.workspace)
    oversized_input = "x" * (MAX_TOOL_INPUT_UTF8_BYTES + 1)

    first = pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__inspect_repository",
            "tool_input": {"payload": oversized_input},
        },
        state=state,
        control=control,
    )
    assert first["hookSpecificOutput"]["permissionDecision"] == "deny"

    second = pretool_policy_output(
        policy,
        {"tool_name": _ExplosiveToolName(), "tool_input": {}},
        state=state,
        control=control,
    )
    assert second["hookSpecificOutput"]["permissionDecisionReason"] == (
        "runtime-budget: tool-call budget exhausted"
    )
    assert state.terminal_status is TerminalStatus.BUDGET_EXCEEDED
    record = _journal_records(control)[-1]
    assert record["event"] == "budget_denied"
    payload = record["payload"]
    assert isinstance(payload, dict)
    assert payload["tool_name_state"] == "unvalidated"
    assert "tool_name" not in payload
