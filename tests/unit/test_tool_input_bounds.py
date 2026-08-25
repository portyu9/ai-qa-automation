from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.runtime_hooks as runtime_hooks
from ai_qa_automation.models import AgentRunState, ValidationStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.redaction import sanitize
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.tool_input_bounds import (
    MAX_TOOL_INPUT_UTF8_BYTES,
    MAX_TOOL_NAME_UTF8_BYTES,
    ToolInputBoundsError,
    bounded_json_loads,
    tool_input_fingerprint,
    validate_tool_request,
)


def make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir(exist_ok=True)
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
        lease_id="bounded-input-test",
    )


def make_live_services(control: RuntimeControl) -> LiveRuntimeServices:
    state = AgentRunState(objective="bound tool input", workspace=str(control.workspace))
    return LiveRuntimeServices(
        workspace=control.workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=5,
        max_repeated_action=2,
        control=control,
    )


def test_incremental_fingerprint_preserves_pretool_canonical_semantics() -> None:
    value = {"z": "é", "a": [1, 2], "token": "not-a-secret-pattern"}
    safe = cast(dict[str, Any], sanitize(value))
    rendered = json.dumps(safe, sort_keys=True, separators=(",", ":"), default=str)
    expected = hashlib.sha256(f"tool:{rendered}".encode()).hexdigest()

    assert tool_input_fingerprint("tool", safe) == expected


def test_pretool_rejects_oversized_input_before_fingerprint_policy_or_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = make_control(tmp_path)
    policy = PolicyEngine(tmp_path, control.workspace)
    state = AgentRunState(objective="oversized request", workspace=str(control.workspace))
    oversized = "x" * (MAX_TOOL_INPUT_UTF8_BYTES + 1)

    monkeypatch.setattr(
        runtime_hooks,
        "_input_fingerprint",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fingerprint reached")),
    )
    monkeypatch.setattr(
        policy,
        "authorize_tool",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("policy reached")),
    )

    result = runtime_hooks.pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__inspect_repository",
            "tool_input": {"payload": oversized},
        },
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert hook["permissionDecisionReason"].startswith("tool-input-bounds:")
    assert control.budget.snapshot().tool_calls == 0
    assert state.tool_call_count == 0
    journal = control.journal.path.read_text(encoding="utf-8")
    assert oversized[:128] not in journal
    assert "reason_code" in journal


def test_pretool_rejects_malformed_json_field_before_budget(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    policy = PolicyEngine(tmp_path, control.workspace)

    result = runtime_hooks.pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__validate_json_contract",
            "tool_input": {"instance_json": "{", "schema_json": "{}"},
        },
        control=control,
    )

    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "not valid bounded JSON" in result["hookSpecificOutput"]["permissionDecisionReason"]
    assert control.budget.snapshot().tool_calls == 0


def test_json_depth_is_rejected_before_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = "[" * 65 + "0" + "]" * 65
    called = False

    def explode(_raw: str) -> Any:
        nonlocal called
        called = True
        raise AssertionError("json.loads must not run")

    import ai_qa_automation.runtime.tool_input_bounds as bounds

    monkeypatch.setattr(bounds.json, "loads", explode)
    with pytest.raises(ToolInputBoundsError, match="nesting-depth"):
        bounded_json_loads(raw, label="deep-json")
    assert called is False


def test_live_service_rejects_browser_candidate_overflow_before_accounting(
    tmp_path: Path,
) -> None:
    control = make_control(tmp_path)
    services = make_live_services(control)
    candidates = [
        {"locator": f"get_by_role('button', name='Save {index}')", "strategy": "role"}
        for index in range(21)
    ]

    with pytest.raises(ToolInputBoundsError, match="20-candidate"):
        services.consume(
            "verify_locator_candidates",
            {
                "url": "https://example.test",
                "original_locator": "get_by_role('button', name='Save')",
                "candidates_json": json.dumps(candidates),
            },
        )
    assert services.state.tool_call_count == 0


def test_non_json_and_non_finite_values_are_rejected() -> None:
    with pytest.raises(ToolInputBoundsError, match="JSON-compatible"):
        validate_tool_request("tool", {"bad": object()})
    with pytest.raises(ToolInputBoundsError, match="non-finite"):
        validate_tool_request("tool", {"bad": float("nan")})


def test_posttool_failure_keeps_uncertainty_when_input_is_invalid(tmp_path: Path) -> None:
    state = AgentRunState(objective="validate", workspace=str(tmp_path), change_revision=2)

    result = runtime_hooks.posttool_failure_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {"bad": float("nan")},
            "error": "synthetic failure",
        },
        state=state,
    )

    assert len(state.validation_results) == 1
    item = state.validation_results[0]
    assert item.status is ValidationStatus.NOT_VERIFIED
    assert len(item.details["input_hash"]) == 64
    assert "NOT_VERIFIED" in result["hookSpecificOutput"]["additionalContext"]


def test_browser_candidate_limit_handles_prefixed_and_internal_names() -> None:
    candidates = [{"locator": f"l{index}", "strategy": "css"} for index in range(21)]
    tool_input = {
        "url": "https://example.test",
        "original_locator": "#save",
        "candidates_json": json.dumps(candidates),
    }

    for name in ("verify_locator_candidates", "mcp__qa__verify_locator_candidates"):
        with pytest.raises(ToolInputBoundsError, match="20-candidate"):
            validate_tool_request(name, tool_input)


def test_tool_name_is_bounded_before_fingerprinting() -> None:
    oversized_name = "t" * (MAX_TOOL_NAME_UTF8_BYTES + 1)

    with pytest.raises(ToolInputBoundsError, match="tool name"):
        validate_tool_request(oversized_name, {})
