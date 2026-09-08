from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.journal import RunJournal
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


def _patch_runtime(
    monkeypatch: pytest.MonkeyPatch,
    provider_calls: list[str],
    *,
    patch_sessions: bool = True,
) -> None:
    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            provider_calls.append("client_constructed")
            raise AssertionError("provider client must not be constructed after journal ambiguity")

    async def forbidden_sessions(**_kwargs: object) -> None:
        provider_calls.append("started")
        raise AssertionError("provider execution must not start after journal ambiguity")

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    if patch_sessions:
        monkeypatch.setattr(agent_module, "execute_sdk_sessions", forbidden_sessions)
    monkeypatch.setattr(
        agent_module,
        "bootstrap_runtime_context",
        lambda **_kwargs: "bounded bootstrap context",
    )
    monkeypatch.setattr(agent_module, "build_internal_mcp_server", lambda _services: (object(), []))
    monkeypatch.setattr(agent_module, "build_external_mcp", lambda _settings, _policy: ({}, {}))
    monkeypatch.setattr(agent_module, "build_permission_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})


def _persisted_state(artifacts: Path) -> AgentRunState:
    state_paths = list(artifacts.glob("*/state.json"))
    assert len(state_paths) == 1
    return StateStore(state_paths[0]).load()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_event", "force_recovery", "failure_mode"),
    [
        ("stale_mutation_recovered_before_bootstrap", True, "exception"),
        ("workspace_lease_acquired", False, "exception"),
        ("control_plane_subject_bound", False, "exception"),
        ("agent_run_started", False, "exception"),
        ("pre_provider_control_plane_revalidation", False, "exception"),
        ("stale_mutation_recovered_before_bootstrap", True, "budget"),
        ("pre_provider_control_plane_revalidation", False, "budget"),
    ],
)
async def test_required_pre_provider_journal_failure_closes_without_provider_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_event: str,
    force_recovery: bool,
    failure_mode: str,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_runtime(
        monkeypatch,
        provider_calls,
        patch_sessions=failed_event != "pre_provider_control_plane_revalidation",
    )

    if force_recovery:
        monkeypatch.setattr(
            agent_module,
            "recover_stale_mutation",
            lambda **_kwargs: {
                "status": "RECOVERED",
                "path": "tests/test_recovered.py",
                "previous_run_id": "run-prior",
            },
        )

    original_try_append = RunJournal.try_append
    attempted_events: list[str] = []

    def fail_required_event(
        self: RunJournal,
        event: str,
        **payload: object,
    ) -> bool:
        attempted_events.append(event)
        if event == failed_event:
            if failure_mode == "budget":
                return False
            raise OSError("post-fsync journal identity is ambiguous")
        return original_try_append(self, event, **payload)

    monkeypatch.setattr(RunJournal, "try_append", fail_required_event)

    result = await run_agent(
        "exercise required pre-provider journal failure",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "before provider execution" in report["summary"].lower()
    assert failed_event in report["summary"]
    if failure_mode == "budget":
        assert "BudgetExceededError" in report["summary"]
    assert attempted_events.count(failed_event) == 1
    assert "agent_run_finished" not in attempted_events
    assert provider_calls == []

    persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]


@pytest.mark.asyncio
async def test_retry_schedule_journal_ambiguity_refuses_replay_before_state_advances(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_runtime(monkeypatch, provider_calls, patch_sessions=False)

    class StartupFailureClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            provider_calls.append("client_constructed")

        async def __aenter__(self) -> StartupFailureClient:
            provider_calls.append("client_entered")
            raise ConnectionError("connection refused before provider query submission")

        async def __aexit__(self, *args: object) -> None:
            provider_calls.append("client_exited")

    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", StartupFailureClient)

    original_try_append = RunJournal.try_append
    attempted_events: list[str] = []

    def fail_retry_schedule(
        self: RunJournal,
        event: str,
        **payload: object,
    ) -> bool:
        attempted_events.append(event)
        if event == "sdk_retry_scheduled":
            raise OSError("retry journal durability is ambiguous")
        return original_try_append(self, event, **payload)

    monkeypatch.setattr(RunJournal, "try_append", fail_retry_schedule)

    result = await run_agent(
        "exercise retry journal authority",
        workspace,
        Settings(
            control_root=control,
            artifact_root=artifacts,
            max_sdk_retries=2,
            sdk_retry_backoff_seconds=0.1,
            sdk_retry_max_backoff_seconds=0.1,
        ),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "before scheduling an Agent SDK retry" in report["summary"]
    assert "sdk_retry_scheduled" in report["summary"]
    assert "OSError" in report["summary"]
    assert attempted_events.count("pre_provider_control_plane_revalidation") == 1
    assert attempted_events.count("sdk_retry_scheduled") == 1
    assert "agent_run_finished" not in attempted_events
    assert provider_calls == ["client_constructed", "client_entered"]

    persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]
    assert persisted.retry_count == 0
    assert all("scheduling bounded retry" not in item for item in persisted.observations)
