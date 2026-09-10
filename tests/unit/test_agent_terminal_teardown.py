from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import TerminalStatus
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
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


def _patch_provider_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError(
                "provider client construction is owned by the patched session runner"
            )

    async def fail_sessions(**_kwargs: object) -> None:
        raise RuntimeError("deterministic provider failure")

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "execute_sdk_sessions", fail_sessions)
    monkeypatch.setattr(
        agent_module,
        "bootstrap_runtime_context",
        lambda **_kwargs: "bounded bootstrap context",
    )
    monkeypatch.setattr(agent_module, "build_internal_mcp_server", lambda _services: (object(), []))
    monkeypatch.setattr(agent_module, "build_external_mcp", lambda _settings, _policy: ({}, {}))
    monkeypatch.setattr(agent_module, "build_permission_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})


def _persisted_state(artifacts: Path) -> tuple[Path, object]:
    state_paths = list(artifacts.glob("*/state.json"))
    assert len(state_paths) == 1
    state_path = state_paths[0]
    return state_path.parent, StateStore(state_path).load()


@pytest.mark.asyncio
async def test_terminal_journal_ambiguity_returns_infrastructure_report_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    _patch_provider_failure(monkeypatch)
    original_try_append = RunJournal.try_append
    attempted_events: list[str] = []

    def fail_terminal_revalidation(
        self: RunJournal,
        event: str,
        **payload: object,
    ) -> bool:
        attempted_events.append(event)
        if event == "terminal_control_plane_revalidation":
            raise OSError("post-fsync journal identity is ambiguous")
        return original_try_append(self, event, **payload)

    monkeypatch.setattr(RunJournal, "try_append", fail_terminal_revalidation)

    result = await run_agent(
        "exercise terminal journal failure",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "terminal journal persistence could not be guaranteed" in report["summary"].lower()
    assert attempted_events.count("terminal_control_plane_revalidation") == 1
    assert "agent_run_finished" not in attempted_events

    _run_dir, persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]


@pytest.mark.asyncio
async def test_workspace_lease_release_failure_is_reported_after_single_release_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    _patch_provider_failure(monkeypatch)
    original_release = WorkspaceLease.release
    release_calls = 0

    def release_then_fail(self: WorkspaceLease, **kwargs: Any) -> None:
        nonlocal release_calls
        release_calls += 1
        original_release(self, **kwargs)
        raise OSError("post-release authority verification failed")

    monkeypatch.setattr(WorkspaceLease, "release", release_then_fail)

    result = await run_agent(
        "exercise workspace lease teardown failure",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert release_calls == 1
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "workspace lease release could not be guaranteed" in report["summary"].lower()

    run_dir, persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert persisted.terminal_reason == report["summary"]

    records = [json.loads(line) for line in (run_dir / "journal.jsonl").read_text().splitlines()]
    events = [record["event"] for record in records]
    assert events[-2:] == ["workspace_lease_release_failed", "agent_run_finished"]
    assert records[-1]["payload"]["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
