from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.runtime_hooks as runtime_hooks
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.tool_input_bounds import (
    ToolInputBoundsError,
    bounded_json_loads,
    validate_tool_request,
)


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run"
    return RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=5,
            max_network_calls=5,
            max_mutations=2,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="strict-json-test",
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"role":"reader","role":"admin"}',
        '{"outer":{"enabled":false,"enabled":true}}',
    ],
)
def test_bounded_json_rejects_duplicate_object_keys_at_any_depth(raw: str) -> None:
    with pytest.raises(ToolInputBoundsError) as caught:
        bounded_json_loads(raw, label="ambiguous-json")

    assert caught.value.code == "duplicate_json_key"
    assert "duplicate JSON key" in str(caught.value)


@pytest.mark.parametrize("raw", ["NaN", "Infinity", "-Infinity", '{"value":NaN}'])
def test_bounded_json_rejects_non_standard_numeric_constants(raw: str) -> None:
    with pytest.raises(ToolInputBoundsError) as caught:
        bounded_json_loads(raw, label="non-standard-json")

    assert caught.value.code == "non_standard_json_constant"
    assert "non-standard JSON numeric constant" in str(caught.value)


def test_bounded_json_keeps_same_key_names_in_distinct_objects_unambiguous() -> None:
    assert bounded_json_loads('[{"id":1},{"id":2}]', label="valid-json") == [
        {"id": 1},
        {"id": 2},
    ]


def test_json_contract_request_rejects_ambiguous_schema_before_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _control(tmp_path)
    policy = PolicyEngine(tmp_path, control.workspace)
    state = AgentRunState(objective="validate JSON contract", workspace=str(control.workspace))

    monkeypatch.setattr(
        policy,
        "authorize_tool",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("policy reached")),
    )
    result = runtime_hooks.pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__validate_json_contract",
            "tool_input": {
                "instance_json": "{}",
                "schema_json": '{"required":["id"],"required":[]}',
            },
        },
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert hook["permissionDecisionReason"].startswith("tool-input-bounds:")
    assert "duplicate JSON key" in hook["permissionDecisionReason"]
    assert control.budget.snapshot().tool_calls == 1
    assert state.tool_call_count == 1


def test_live_service_defense_in_depth_rejects_ambiguous_json_before_accounting(
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    state = AgentRunState(objective="validate JSON contract", workspace=str(control.workspace))
    services = LiveRuntimeServices(
        workspace=control.workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=5,
        max_repeated_action=2,
        control=control,
    )

    with pytest.raises(ToolInputBoundsError) as caught:
        services.consume(
            "validate_json_contract",
            {
                "instance_json": '{"id":1,"id":2}',
                "schema_json": "{}",
            },
        )

    assert caught.value.code == "duplicate_json_key"
    assert state.tool_call_count == 0


def test_validate_tool_request_rejects_non_standard_contract_constant() -> None:
    with pytest.raises(ToolInputBoundsError) as caught:
        validate_tool_request(
            "mcp__qa__validate_json_contract",
            {"instance_json": '{"value":NaN}', "schema_json": "{}"},
        )

    assert caught.value.code == "non_standard_json_constant"
