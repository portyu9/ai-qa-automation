from __future__ import annotations

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

    assert await pre(
        _internal_input("mcp__qa__inspect_repository"),
        "toolu-second",
        cast(Any, None),
    ) == {}
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
    assert "bounded non-empty tool_use_id" in denied["hookSpecificOutput"][
        "permissionDecisionReason"
    ]
    assert pre_calls == []

    assert await pre(internal, "toolu-valid", cast(Any, None)) == {}
    assert pre_calls == ["mcp__qa__inspect_repository"]
