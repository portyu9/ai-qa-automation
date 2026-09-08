from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.state import StateStore


def _runtime_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    control = tmp_path / "control"
    workspace = tmp_path / "target"
    artifacts = tmp_path / "artifacts"
    (control / ".claude").mkdir(parents=True)
    workspace.mkdir()
    (control / "CLAUDE.md").write_text("trusted instructions\n", encoding="utf-8")
    (control / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    for skill in (
        "investigate-test-failure",
        "self-heal-test",
        "generate-test",
        "prioritize-regression",
        "performance-test",
    ):
        skill_file = control / ".claude" / "skills" / skill / "SKILL.md"
        skill_file.parent.mkdir(parents=True, exist_ok=True)
        skill_file.write_text(f"{skill} authority\n", encoding="utf-8")
    return control, workspace, artifacts


def _patch_pre_provider_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    provider_calls: list[str],
) -> None:
    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError(
                "provider client construction is owned by the patched session runner"
            )

    async def forbidden_sessions(**_kwargs: object) -> None:
        provider_calls.append("started")
        raise AssertionError("provider execution must not start after initialization failure")

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "execute_sdk_sessions", forbidden_sessions)
    monkeypatch.setattr(
        agent_module,
        "bootstrap_runtime_context",
        lambda **_kwargs: "bounded bootstrap context",
    )
    monkeypatch.setattr(
        agent_module,
        "build_internal_mcp_server",
        lambda _services: (object(), []),
    )
    monkeypatch.setattr(
        agent_module,
        "build_external_mcp",
        lambda _settings, _policy: ({}, {}),
    )
    monkeypatch.setattr(
        agent_module,
        "build_permission_handler",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})


def _persisted_state(artifacts: Path) -> AgentRunState:
    state_paths = list(artifacts.glob("*/state.json"))
    assert len(state_paths) == 1
    return StateStore(state_paths[0]).load()


def _journal_events(artifacts: Path) -> list[dict[str, object]]:
    journal_paths = list(artifacts.glob("*/journal.jsonl"))
    assert len(journal_paths) == 1
    return [
        json.loads(line)
        for line in journal_paths[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_stage", "error_type", "expected_phase"),
    [
        ("bootstrap", OSError, "BOOTSTRAP"),
        ("external_mcp", ValueError, "BOOTSTRAP"),
        ("operational_sync", RuntimeError, "RUNNING"),
    ],
)
async def test_expected_pre_provider_initialization_failure_returns_durable_infrastructure_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
    error_type: type[Exception],
    expected_phase: str,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_pre_provider_dependencies(monkeypatch, provider_calls)

    def fail() -> None:
        raise error_type("synthetic pre-provider failure")

    if failure_stage == "bootstrap":
        monkeypatch.setattr(
            agent_module,
            "bootstrap_runtime_context",
            lambda **_kwargs: fail(),
        )
    elif failure_stage == "external_mcp":
        monkeypatch.setattr(
            agent_module,
            "build_external_mcp",
            lambda *_args, **_kwargs: fail(),
        )
    else:
        monkeypatch.setattr(
            agent_module,
            "_sync_operational_state",
            lambda *_args: fail(),
        )

    result = await run_agent(
        "exercise expected pre-provider initialization failure",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "Pre-provider runtime initialization" in report["summary"]
    assert error_type.__name__ in report["summary"]
    assert provider_calls == []

    persisted = _persisted_state(artifacts)
    assert persisted.phase == "TERMINAL"
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]

    events = _journal_events(artifacts)
    failure_events = [
        event for event in events if event.get("event") == "pre_provider_initialization_failed"
    ]
    assert len(failure_events) == 1
    assert failure_events[0]["failed_phase"] == expected_phase
    assert failure_events[0]["error_type"] == error_type.__name__
    assert not any(event.get("event") == "agent_run_started" for event in events)
    assert any(event.get("event") == "agent_run_finished" for event in events)


@pytest.mark.asyncio
async def test_unexpected_pre_provider_programming_failure_still_propagates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_pre_provider_dependencies(monkeypatch, provider_calls)

    def fail_bootstrap(**_kwargs: object) -> str:
        raise AssertionError("synthetic programming failure")

    monkeypatch.setattr(agent_module, "bootstrap_runtime_context", fail_bootstrap)

    with pytest.raises(AssertionError, match="synthetic programming failure"):
        await run_agent(
            "exercise unexpected pre-provider programming failure",
            workspace,
            Settings(control_root=control, artifact_root=artifacts),
        )

    assert provider_calls == []
    persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is None


@pytest.mark.asyncio
async def test_expected_exception_after_provider_start_is_not_reclassified_as_pre_provider_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_pre_provider_dependencies(monkeypatch, provider_calls)

    async def successful_sessions(**_kwargs: object) -> SimpleNamespace:
        provider_calls.append("started")
        return SimpleNamespace(
            final_text="provider completed",
            result_subtype="success",
            last_retry_decision=None,
            pre_provider_denial=None,
            failure=None,
        )

    def fail_terminal_outcome(
        *_args: object,
        **_kwargs: object,
    ) -> tuple[TerminalStatus, str]:
        raise ValueError("synthetic post-provider programming failure")

    monkeypatch.setattr(agent_module, "execute_sdk_sessions", successful_sessions)
    monkeypatch.setattr(
        agent_module,
        "determine_terminal_outcome",
        fail_terminal_outcome,
    )

    with pytest.raises(ValueError, match="synthetic post-provider programming failure"):
        await run_agent(
            "exercise post-provider exception boundary",
            workspace,
            Settings(control_root=control, artifact_root=artifacts),
        )

    assert provider_calls == ["started"]
    events = _journal_events(artifacts)
    assert not any(event.get("event") == "pre_provider_initialization_failed" for event in events)
