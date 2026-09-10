from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime import runtime_hooks


def _hook_callbacks(
    hooks: dict[Any, list[Any]],
) -> tuple[Any, Any, Any]:
    pre = hooks["PreToolUse"][0].hooks[0]
    post = hooks["PostToolUse"][0].hooks[0]
    failure = hooks["PostToolUseFailure"][0].hooks[0]
    return pre, post, failure


def _internal_input(tool_name: str) -> dict[str, Any]:
    return {"tool_name": tool_name, "tool_input": {}}


@pytest.mark.asyncio
async def test_internal_lifecycle_remains_reserved_through_matching_post_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_calls: list[str] = []
    post_calls: list[str] = []

    def fake_pre(_policy: Any, input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        pre_calls.append(cast(str, input_data["tool_name"]))
        return {}

    def fake_post(input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        post_calls.append(cast(str, input_data["tool_name"]))
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "closed",
            }
        }

    monkeypatch.setattr(runtime_hooks, "pretool_policy_output", fake_pre)
    monkeypatch.setattr(runtime_hooks, "posttool_policy_output", fake_post)
    hooks = runtime_hooks.build_hooks(cast(Any, object()))
    pre, post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))

    first = _internal_input("mcp__qa__inspect_browser")
    second = _internal_input("mcp__qa__apply_locator_heal")
    third = _internal_input("mcp__qa__inspect_repository")

    assert await pre(first, "toolu-first", cast(Any, None)) == {}

    denied = await pre(second, "toolu-second", cast(Any, None))
    denial = denied["hookSpecificOutput"]
    assert denial["permissionDecision"] == "deny"
    assert "runtime-serialization" in denial["permissionDecisionReason"]
    assert "still active" in denial["permissionDecisionReason"]
    assert pre_calls == ["mcp__qa__inspect_browser"]

    closed = await post(first, "toolu-first", cast(Any, None))
    assert closed["hookSpecificOutput"]["additionalContext"] == "closed"
    assert post_calls == ["mcp__qa__inspect_browser"]

    assert await pre(third, "toolu-third", cast(Any, None)) == {}
    assert pre_calls == ["mcp__qa__inspect_browser", "mcp__qa__inspect_repository"]


@pytest.mark.asyncio
async def test_busy_internal_lifecycle_persists_precharged_budget_without_state_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre_calls: list[str] = []
    state_saves: list[int] = []
    journal_events: list[tuple[str, dict[str, Any]]] = []
    state = AgentRunState(objective="test durable lifecycle denial", workspace="/workspace")

    class FakeBudget:
        def __init__(self) -> None:
            self.tool_calls = 0

        def charge_tool(self) -> None:
            self.tool_calls += 1

        def snapshot(self) -> SimpleNamespace:
            return SimpleNamespace(tool_calls=self.tool_calls)

    class FakeJournal:
        def append(self, event: str, **payload: Any) -> None:
            journal_events.append((event, payload))

    class FakeControl:
        def __init__(self) -> None:
            self.budget = FakeBudget()
            self.journal = FakeJournal()
            self.persisted_tool_calls: list[int] = []

        def persist(self) -> None:
            self.persisted_tool_calls.append(self.budget.tool_calls)

    class FakeStateStore:
        def save(self, _state: AgentRunState) -> None:
            state_saves.append(_state.tool_call_count)

    control = FakeControl()

    def fake_pre(_policy: Any, input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        pre_calls.append(cast(str, input_data["tool_name"]))
        return {}

    monkeypatch.setattr(runtime_hooks, "pretool_policy_output", fake_pre)
    hooks = runtime_hooks.build_hooks(
        cast(Any, object()),
        state=state,
        state_store=cast(Any, FakeStateStore()),
        control=cast(Any, control),
    )
    pre, _post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))

    assert (
        await pre(
            _internal_input("mcp__qa__inspect_browser"),
            "toolu-first",
            cast(Any, None),
        )
        == {}
    )
    assert control.budget.tool_calls == 1
    assert control.persisted_tool_calls == []
    assert state_saves == []

    state.observations.append("in-flight semantic marker")
    denied = await pre(
        _internal_input("mcp__qa__apply_locator_heal"),
        "toolu-second",
        cast(Any, None),
    )

    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "still active" in denied["hookSpecificOutput"]["permissionDecisionReason"]
    assert control.budget.tool_calls == 2
    assert control.persisted_tool_calls == [2]
    assert state.tool_call_count == 2
    assert state_saves == []
    assert state.observations == ["in-flight semantic marker"]
    assert pre_calls == ["mcp__qa__inspect_browser"]
    assert journal_events == [
        (
            "internal_tool_lifecycle_denied",
            {
                "tool_name": "mcp__qa__apply_locator_heal",
                "reason": (
                    "another framework-owned internal tool lifecycle is still active; "
                    "concurrent internal execution is denied"
                ),
            },
        )
    ]


@pytest.mark.asyncio
async def test_busy_internal_lifecycle_budget_exhaustion_never_checkpoints_active_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_saves: list[int] = []
    journal_events: list[tuple[str, dict[str, Any]]] = []
    state = AgentRunState(objective="test busy budget exhaustion", workspace="/workspace")

    class FakeBudget:
        def __init__(self) -> None:
            self.tool_calls = 0
            self.exhausted = False

        def charge_tool(self) -> None:
            if self.exhausted:
                raise runtime_hooks.BudgetExceededError("tool-call budget exhausted")
            self.tool_calls += 1

        def snapshot(self) -> SimpleNamespace:
            return SimpleNamespace(tool_calls=self.tool_calls)

    class FakeJournal:
        def append(self, event: str, **payload: Any) -> None:
            journal_events.append((event, payload))

    class FakeControl:
        def __init__(self) -> None:
            self.budget = FakeBudget()
            self.journal = FakeJournal()
            self.persisted_tool_calls: list[int] = []

        def persist(self) -> None:
            self.persisted_tool_calls.append(self.budget.tool_calls)

    class FakeStateStore:
        def save(self, _state: AgentRunState) -> None:
            state_saves.append(_state.tool_call_count)

    control = FakeControl()
    monkeypatch.setattr(
        runtime_hooks,
        "pretool_policy_output",
        lambda _policy, _input_data, **_kwargs: {},
    )
    hooks = runtime_hooks.build_hooks(
        cast(Any, object()),
        state=state,
        state_store=cast(Any, FakeStateStore()),
        control=cast(Any, control),
    )
    pre, _post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))

    assert (
        await pre(
            _internal_input("mcp__qa__inspect_browser"),
            "toolu-first",
            cast(Any, None),
        )
        == {}
    )
    control.budget.exhausted = True
    state.observations.append("in-flight semantic marker")

    denied = await pre(
        _internal_input("mcp__qa__inspect_repository"),
        "toolu-second",
        cast(Any, None),
    )

    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert denied["hookSpecificOutput"]["permissionDecisionReason"] == (
        "runtime-budget: tool-call budget exhausted"
    )
    assert control.budget.tool_calls == 1
    assert control.persisted_tool_calls == [1]
    assert state.tool_call_count == 1
    assert state.terminal_status is TerminalStatus.BUDGET_EXCEEDED
    assert state_saves == []
    assert state.observations == ["in-flight semantic marker"]
    assert journal_events == [
        (
            "budget_denied",
            {
                "tool_name": "mcp__qa__inspect_repository",
                "admission": "internal_lifecycle",
                "reason": "tool-call budget exhausted",
            },
        )
    ]


@pytest.mark.asyncio
async def test_admitted_internal_pretool_exception_latches_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentRunState(objective="test pretool lifecycle failure", workspace="/workspace")

    def fail_pre(_policy: Any, _input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("pretool exploded")

    monkeypatch.setattr(runtime_hooks, "pretool_policy_output", fail_pre)
    hooks = runtime_hooks.build_hooks(cast(Any, object()), state=state)
    pre, _post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))

    with pytest.raises(RuntimeError, match="pretool exploded"):
        await pre(
            _internal_input("mcp__qa__inspect_browser"),
            "toolu-first",
            cast(Any, None),
        )

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert "PreToolUse" in cast(str, state.terminal_reason)

    denied = await pre(
        _internal_input("mcp__qa__inspect_repository"),
        "toolu-second",
        cast(Any, None),
    )
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "processing failed" in denied["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event_name", "patched_name", "callback_index"),
    [
        ("PostToolUse", "posttool_policy_output", 1),
        ("PostToolUseFailure", "posttool_failure_output", 2),
    ],
)
async def test_admitted_internal_terminal_hook_exception_latches_infrastructure_failure(
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
    patched_name: str,
    callback_index: int,
) -> None:
    state = AgentRunState(objective="test terminal lifecycle failure", workspace="/workspace")

    monkeypatch.setattr(
        runtime_hooks,
        "pretool_policy_output",
        lambda _policy, _input_data, **_kwargs: {},
    )

    def fail_terminal(_input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("terminal hook exploded")

    monkeypatch.setattr(runtime_hooks, patched_name, fail_terminal)
    hooks = runtime_hooks.build_hooks(cast(Any, object()), state=state)
    callbacks = _hook_callbacks(cast(dict[Any, list[Any]], hooks))
    pre = callbacks[0]
    terminal_hook = callbacks[callback_index]
    internal = _internal_input("mcp__qa__inspect_browser")

    assert await pre(internal, "toolu-first", cast(Any, None)) == {}
    with pytest.raises(RuntimeError, match="terminal hook exploded"):
        await terminal_hook(internal, "toolu-first", cast(Any, None))

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert event_name in cast(str, state.terminal_reason)

    denied = await pre(
        _internal_input("mcp__qa__inspect_repository"),
        "toolu-second",
        cast(Any, None),
    )
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "processing failed" in denied["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.asyncio
async def test_internal_completion_identity_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    post_calls: list[str] = []
    state = AgentRunState(objective="test lifecycle authority", workspace="/workspace")

    monkeypatch.setattr(
        runtime_hooks,
        "pretool_policy_output",
        lambda _policy, _input_data, **_kwargs: {},
    )

    def fake_post(input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        post_calls.append(cast(str, input_data["tool_name"]))
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse"}}

    monkeypatch.setattr(runtime_hooks, "posttool_policy_output", fake_post)
    hooks = runtime_hooks.build_hooks(cast(Any, object()), state=state)
    pre, post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))
    first = _internal_input("mcp__qa__inspect_browser")

    assert await pre(first, "toolu-first", cast(Any, None)) == {}
    rejected = await post(first, "toolu-wrong", cast(Any, None))

    assert post_calls == []
    assert rejected["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True
    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert "lifecycle identity" in cast(str, state.terminal_reason)

    later = await pre(
        _internal_input("mcp__qa__inspect_repository"),
        "toolu-later",
        cast(Any, None),
    )
    assert later["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "does not match" in later["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.asyncio
async def test_matching_failure_hook_releases_internal_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failure_calls: list[str] = []
    pre_calls: list[str] = []

    def fake_pre(_policy: Any, input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        pre_calls.append(cast(str, input_data["tool_name"]))
        return {}

    def fake_failure(input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        failure_calls.append(cast(str, input_data["tool_name"]))
        return {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUseFailure",
                "additionalContext": "failed",
            }
        }

    monkeypatch.setattr(runtime_hooks, "pretool_policy_output", fake_pre)
    monkeypatch.setattr(runtime_hooks, "posttool_failure_output", fake_failure)
    hooks = runtime_hooks.build_hooks(cast(Any, object()))
    pre, _post, failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))
    first = _internal_input("mcp__qa__probe_api")

    assert await pre(first, "toolu-first", cast(Any, None)) == {}
    closed = await failure(first, "toolu-first", cast(Any, None))
    assert closed["hookSpecificOutput"]["additionalContext"] == "failed"
    assert failure_calls == ["mcp__qa__probe_api"]

    assert (
        await pre(
            _internal_input("mcp__qa__inspect_repository"),
            "toolu-second",
            cast(Any, None),
        )
        == {}
    )
    assert pre_calls == ["mcp__qa__probe_api", "mcp__qa__inspect_repository"]


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_use_id", [None, "", "x" * 257])
async def test_invalid_internal_tool_use_id_is_denied_without_poisoning_gate(
    monkeypatch: pytest.MonkeyPatch,
    tool_use_id: str | None,
) -> None:
    pre_calls: list[str] = []

    def fake_pre(_policy: Any, input_data: dict[str, Any], **_kwargs: Any) -> dict[str, Any]:
        pre_calls.append(cast(str, input_data["tool_name"]))
        return {}

    monkeypatch.setattr(runtime_hooks, "pretool_policy_output", fake_pre)
    hooks = runtime_hooks.build_hooks(cast(Any, object()))
    pre, _post, _failure = _hook_callbacks(cast(dict[Any, list[Any]], hooks))
    internal = _internal_input("mcp__qa__inspect_repository")

    denied = await pre(internal, tool_use_id, cast(Any, None))
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert (
        "bounded non-empty tool_use_id" in denied["hookSpecificOutput"]["permissionDecisionReason"]
    )
    assert pre_calls == []

    assert await pre(internal, "toolu-valid", cast(Any, None)) == {}
    assert pre_calls == ["mcp__qa__inspect_repository"]
