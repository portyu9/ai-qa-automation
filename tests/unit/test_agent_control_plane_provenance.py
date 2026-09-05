from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ai_qa_automation import agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import ControlPlaneRevalidationStatus, TerminalStatus
from ai_qa_automation.runtime.workspace_lease import WorkspaceBusyError, WorkspaceLease


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


@pytest.mark.asyncio
async def test_run_agent_fails_before_model_when_control_subject_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    unsafe = control / ".claude" / "unsafe-link"
    try:
        unsafe.symlink_to(control / "CLAUDE.md")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("model client must not be constructed without control provenance")

    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    result = await run_agent(
        "inspect target safely",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert (
        report["provenance"]["control_plane_revalidation_status"]
        == ControlPlaneRevalidationStatus.UNAVAILABLE.value
    )
    assert report["provenance"]["control_plane_subject"] is None
    assert result["agent_result"] == ""
    assert len(list(artifacts.glob("*/state.json"))) == 1


@pytest.mark.asyncio
async def test_early_blocked_report_preserves_bound_control_subject_without_model_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("model client must not be constructed after lease denial")

    def deny_lease(self: WorkspaceLease) -> None:
        raise WorkspaceBusyError("workspace already leased")

    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(WorkspaceLease, "acquire", deny_lease)
    result = await run_agent(
        "inspect target safely",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    subject = report["provenance"]["control_plane_subject"]
    assert report["terminal_status"] == TerminalStatus.BLOCKED.value
    assert subject is not None
    assert subject["subject_digest"].startswith("sha256:")
    assert (
        report["provenance"]["control_plane_revalidation_status"]
        == ControlPlaneRevalidationStatus.BOUND.value
    )
    assert result["agent_result"] == ""


@pytest.mark.asyncio
async def test_run_agent_rejects_control_drift_during_git_observation_before_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("model client must not be constructed after provenance drift")

    def drift_during_git_observation(root: Path) -> tuple[str, bool]:
        assert root == control
        skill = control / ".claude" / "skills" / "generate-test" / "SKILL.md"
        skill.write_text("drifted during Git observation\n", encoding="utf-8")
        return "d" * 40, False

    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "_observe_control_git_subject", drift_during_git_observation)
    result = await run_agent(
        "inspect target safely",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert report["provenance"]["control_plane_subject"] is None
    assert (
        report["provenance"]["control_plane_revalidation_status"]
        == ControlPlaneRevalidationStatus.UNAVAILABLE.value
    )
    assert result["agent_result"] == ""


@pytest.mark.asyncio
async def test_run_agent_revalidates_control_subject_immediately_before_provider_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)

    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError("provider client must not start after pre-provider control drift")

    def drift_after_bootstrap(**kwargs: object) -> str:
        del kwargs
        skill = control / ".claude" / "skills" / "generate-test" / "SKILL.md"
        skill.write_text("drifted after bootstrap before provider\n", encoding="utf-8")
        return "bounded bootstrap context"

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "bootstrap_runtime_context", drift_after_bootstrap)
    monkeypatch.setattr(agent_module, "build_internal_mcp_server", lambda services: (object(), []))
    monkeypatch.setattr(agent_module, "build_external_mcp", lambda settings, policy: ({}, {}))
    monkeypatch.setattr(agent_module, "build_permission_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})
    result = await run_agent(
        "inspect target safely",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.BLOCKED.value
    assert (
        report["provenance"]["control_plane_revalidation_status"]
        == ControlPlaneRevalidationStatus.DRIFTED.value
    )
    assert report["provenance"]["control_plane_subject"] is not None
    assert result["agent_result"] == ""


@pytest.mark.asyncio
async def test_run_agent_fails_closed_when_control_subject_becomes_unavailable_before_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)

    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError(
                "provider client must not start without revalidated control authority"
            )

    def remove_authority_after_bootstrap(**kwargs: object) -> str:
        del kwargs
        shutil.rmtree(control / ".claude")
        return "bounded bootstrap context"

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "bootstrap_runtime_context", remove_authority_after_bootstrap)
    monkeypatch.setattr(agent_module, "build_internal_mcp_server", lambda services: (object(), []))
    monkeypatch.setattr(agent_module, "build_external_mcp", lambda settings, policy: ({}, {}))
    monkeypatch.setattr(agent_module, "build_permission_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})

    result = await run_agent(
        "inspect target safely",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert (
        report["provenance"]["control_plane_revalidation_status"]
        == ControlPlaneRevalidationStatus.UNAVAILABLE.value
    )
    assert report["provenance"]["control_plane_subject"] is not None
    assert result["agent_result"] == ""
