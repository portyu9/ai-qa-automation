from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar

import pytest

from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.runtime.sdk_result_bounds import MAX_SDK_RESULT_UTF8_BYTES


class FakeClaudeAgentOptions:
    def __init__(self, **kwargs: Any) -> None:
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeResultMessage:
    def __init__(
        self,
        *,
        result: object = "Model completed without deterministic execution.",
        subtype: object = "success",
        is_error: object = False,
        total_cost_usd: object = 0.01,
        usage: object = None,
    ) -> None:
        self.result = result
        self.subtype = subtype
        self.is_error = is_error
        self.total_cost_usd = total_cost_usd
        self.usage = (
            {"input_tokens": 10, "output_tokens": 5} if usage is None else usage
        )


class FakeClaudeSDKClient:
    messages: ClassVar[list[object]] = []
    query_count: ClassVar[int] = 0

    def __init__(self, *, options: Any) -> None:
        self.options = options

    async def __aenter__(self) -> FakeClaudeSDKClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def query(self, _prompt: str) -> None:
        type(self).query_count += 1

    async def receive_response(self):
        for message in type(self).messages:
            yield message


class FakeHookMatcher:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakePermissionResultAllow:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakePermissionResultDeny:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


def fake_tool(_name: str, _description: str, _schema: dict[str, Any]):
    def decorator(function):
        return function

    return decorator


def fake_create_sdk_mcp_server(*, name: str, version: str, tools: list[Any]) -> dict[str, Any]:
    return {"name": name, "version": version, "tools": tools}


@pytest.fixture
def fake_sdk(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    module = ModuleType("claude_agent_sdk")
    module.ClaudeAgentOptions = FakeClaudeAgentOptions
    module.ClaudeSDKClient = FakeClaudeSDKClient
    module.ResultMessage = FakeResultMessage
    module.HookMatcher = FakeHookMatcher
    module.PermissionResultAllow = FakePermissionResultAllow
    module.PermissionResultDeny = FakePermissionResultDeny
    module.tool = fake_tool
    module.create_sdk_mcp_server = fake_create_sdk_mcp_server
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", module)
    FakeClaudeSDKClient.messages = []
    FakeClaudeSDKClient.query_count = 0
    return module


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        control_root=Path.cwd(),
        artifact_root=tmp_path / "artifacts",
        max_turns=3,
        max_tool_calls=4,
        max_cost_usd=0.5,
    )


async def _run(tmp_path: Path, messages: list[object]) -> dict[str, Any]:
    target = tmp_path / "target"
    target.mkdir()
    FakeClaudeSDKClient.messages = messages
    return await run_agent("Inspect the target.", target, _settings(tmp_path))


def _persisted_state(tmp_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    path = tmp_path / "artifacts" / result["report"]["run_id"] / "state.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.asyncio
async def test_oversized_sdk_result_fails_closed_without_retaining_provider_text(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    marker = "provider-private-marker"
    result = await _run(
        tmp_path,
        [FakeResultMessage(result=marker + "x" * MAX_SDK_RESULT_UTF8_BYTES)],
    )

    assert result["report"]["terminal_status"] == "INFRASTRUCTURE_FAILURE"
    assert result["agent_result"] == ""
    assert "result_bytes" in result["report"]["summary"]
    assert marker not in result["report"]["summary"]
    assert FakeClaudeSDKClient.query_count == 1
    state = _persisted_state(tmp_path, result)
    assert state["cost"] == 0.0
    assert state["token_usage"] == 0


@pytest.mark.asyncio
async def test_duplicate_sdk_terminal_results_are_rejected_as_ambiguous(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [FakeResultMessage(), FakeResultMessage(result="second")])

    assert result["report"]["terminal_status"] == "INFRASTRUCTURE_FAILURE"
    assert result["agent_result"] == ""
    assert "duplicate_result_message" in result["report"]["summary"]
    assert FakeClaudeSDKClient.query_count == 1
    state = _persisted_state(tmp_path, result)
    assert state["cost"] == 0.0
    assert state["token_usage"] == 0


@pytest.mark.asyncio
async def test_missing_sdk_terminal_result_is_provider_infrastructure_failure(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [])

    assert result["report"]["terminal_status"] == "INFRASTRUCTURE_FAILURE"
    assert "missing_result_message" in result["report"]["summary"]
    assert FakeClaudeSDKClient.query_count == 1


@pytest.mark.asyncio
async def test_nonfinite_sdk_cost_never_enters_persisted_state(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [FakeResultMessage(total_cost_usd=float("nan"))])

    assert result["report"]["terminal_status"] == "INFRASTRUCTURE_FAILURE"
    assert result["agent_result"] == ""
    assert "cost_non_finite" in result["report"]["summary"]
    state = _persisted_state(tmp_path, result)
    assert state["cost"] == 0.0
    assert state["token_usage"] == 0


@pytest.mark.asyncio
async def test_reported_sdk_cost_above_runtime_budget_cannot_finish_verified(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [FakeResultMessage(total_cost_usd=0.5001)])

    assert result["report"]["terminal_status"] == "BUDGET_EXCEEDED"
    assert result["agent_result"] == "Model completed without deterministic execution."
    assert FakeClaudeSDKClient.query_count == 1
    state = _persisted_state(tmp_path, result)
    assert state["cost"] == 0.5001
    assert state["token_usage"] == 15


@pytest.mark.asyncio
async def test_sdk_error_flag_cannot_be_promoted_by_success_subtype(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [FakeResultMessage(subtype="success", is_error=True)])

    assert result["report"]["terminal_status"] == "FAILURE"
    assert result["report"]["summary"] == "Agent result subtype: sdk_error"
    assert FakeClaudeSDKClient.query_count == 1


@pytest.mark.asyncio
async def test_malformed_sdk_error_flag_is_protocol_failure(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    result = await _run(tmp_path, [FakeResultMessage(is_error="false")])

    assert result["report"]["terminal_status"] == "INFRASTRUCTURE_FAILURE"
    assert result["agent_result"] == ""
    assert "is_error_type" in result["report"]["summary"]
    assert FakeClaudeSDKClient.query_count == 1
