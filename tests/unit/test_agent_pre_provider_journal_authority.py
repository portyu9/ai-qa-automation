from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import TerminalStatus
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


def _patch_runtime(monkeypatch: pytest.MonkeyPatch, provider_calls: list[str]) -> None:
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
        raise AssertionError("provider execution must not start after journal ambiguity")

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
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


def _persisted_state(artifacts: Path) -> object:
    state_paths = list(artifacts.glob("*/state.json"))
    assert len(state_paths) == 1
    return StateStore(state_paths[0]).load()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_event", "force_recovery"),
    [
        ("stale_mutation_recovered_before_bootstrap", True),
        ("workspace_lease_acquired", False),
        ("control_plane_subject_bound", False),
        ("agent_run_started", False),
    ],
)
async def test_required_pre_provider_journal_ambiguity_fails_closed_without_provider_submission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_event: str,
    force_recovery: bool,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    provider_calls: list[str] = []
    _patch_runtime(monkeypatch, provider_calls)

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
    assert attempted_events.count(failed_event) == 1
    assert "agent_run_finished" not in attempted_events
    assert provider_calls == []

    persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]
