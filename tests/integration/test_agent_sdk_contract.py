from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent, run_agent_sync
from ai_qa_automation.config import Settings


class FakeClaudeAgentOptions:
    last_kwargs: ClassVar[dict[str, Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        type(self).last_kwargs = kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)


class FakeResultMessage:
    def __init__(self) -> None:
        self.result = "Model completed without deterministic execution."
        self.subtype = "success"
        self.total_cost_usd = 0.01
        self.usage = {"input_tokens": 10, "output_tokens": 5}


class FakeClaudeSDKClient:
    def __init__(self, *, options: Any) -> None:
        self.options = options
        self.prompt = ""

    async def __aenter__(self) -> FakeClaudeSDKClient:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def query(self, prompt: str) -> None:
        self.prompt = prompt

    async def receive_response(self):
        yield FakeResultMessage()


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
    return module


def runtime_settings(tmp_path: Path) -> Settings:
    return Settings(
        control_root=Path.cwd(),
        artifact_root=tmp_path / "artifacts",
        max_turns=3,
        max_tool_calls=4,
        max_cost_usd=0.5,
    )


@pytest.mark.asyncio
async def test_live_runtime_contract_is_strict_and_model_success_is_not_pass(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    result = await run_agent(
        "Inspect the target and report evidence.",
        target,
        runtime_settings(tmp_path),
    )

    report = result["report"]
    assert report["terminal_status"] == "NOT_VERIFIED"
    assert report["validation_results"] == []
    assert report["provenance"]["objective_gate_id"] == "NOT_SUPPLIED"
    assert "provenance" not in result

    options = FakeClaudeAgentOptions.last_kwargs
    assert options["tools"] == []
    assert options["setting_sources"] == ["project"]
    assert options["skills"] == [
        "investigate-test-failure",
        "self-heal-test",
        "generate-test",
        "prioritize-regression",
        "performance-test",
    ]
    assert options["strict_mcp_config"] is True
    assert options["permission_mode"] == "default"
    assert "Bash" in options["disallowed_tools"]
    assert "WebSearch" in options["disallowed_tools"]
    assert all(name.startswith("mcp__qa__") for name in options["allowed_tools"])
    assert len(options["allowed_tools"]) == 18
    assert "mcp__qa__safe_replace_test_text" not in options["allowed_tools"]
    assert "mcp__qa__search_test_coverage" in options["allowed_tools"]
    assert "mcp__qa__verify_locator_candidates" in options["allowed_tools"]
    assert "mcp__qa__apply_locator_heal" in options["allowed_tools"]


@pytest.mark.asyncio
async def test_external_mcp_is_registered_but_not_blanket_auto_approved(
    tmp_path: Path,
    fake_sdk: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    external_server = {"type": "stdio", "command": "provider"}

    monkeypatch.setattr(
        agent_module,
        "build_external_mcp",
        lambda _settings, _policy: ({"github": external_server}, {}),
    )

    await run_agent(
        "Inspect provider evidence only if policy permits it.",
        target,
        runtime_settings(tmp_path),
    )

    options = FakeClaudeAgentOptions.last_kwargs
    assert options["mcp_servers"]["github"] is external_server
    assert options["mcp_servers"]["qa"]["name"] == "qa"
    assert all(not name.startswith("mcp__github") for name in options["allowed_tools"])
    assert options["permission_mode"] == "default"
    assert callable(options["can_use_tool"])


@pytest.mark.asyncio
async def test_objective_gate_contract_has_one_canonical_report_provenance_surface(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    target = tmp_path / "target"
    target.mkdir()

    result = await run_agent(
        "Run the exact bounded objective validation.",
        target,
        runtime_settings(tmp_path),
        objective_gate_id="pytest:objective-exact",
    )

    assert result["report"]["terminal_status"] == "NOT_VERIFIED"
    assert result["report"]["provenance"]["objective_gate_id"] == "pytest:objective-exact"
    assert "provenance" not in result


def test_sync_entry_point_preserves_objective_contract(
    tmp_path: Path,
    fake_sdk: ModuleType,
) -> None:
    target = tmp_path / "target"
    target.mkdir()

    result = run_agent_sync(
        "Use the synchronous application entry point.",
        target,
        runtime_settings(tmp_path),
        objective_gate_id="pytest:sync-objective",
    )

    assert result["report"]["terminal_status"] == "NOT_VERIFIED"
    assert result["report"]["provenance"]["objective_gate_id"] == "pytest:sync-objective"
