from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ai_qa_automation.agent as agent_module
import ai_qa_automation.runtime.workspace_freshness as workspace_freshness_module
from ai_qa_automation.agent import _enforce_terminal_workspace_freshness
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import (
    AgentRunState,
    MCPStatus,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import (
    posttool_policy_output,
    pretool_policy_output,
)
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
    observe_workspace_freshness,
)
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-terminal-freshness-git-home"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    result = subprocess.run(
        [executable, *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.rstrip("\r\n")


def _init_repo(repo: Path) -> None:
    _require_descriptor_authority()
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")


def _runtime(
    tmp_path: Path,
) -> tuple[Path, AgentRunState, RuntimeControl, StateStore, LiveRuntimeServices]:
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    run_dir = tmp_path / "run"
    state = AgentRunState(objective="prove workspace freshness", workspace=str(workspace))
    store = StateStore(run_dir / "state.json")
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-terminal-freshness",
        max_repeated_action=5,
    )
    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=control.workspace_identity,
    ).snapshot()
    assert snapshot.fingerprint_complete is True
    control.set_workspace_fingerprint(snapshot.fingerprint)
    store.save(state)
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=EvidenceStore(tmp_path / "artifacts", state.run_id),
        policy=PolicyEngine(tmp_path / "control", workspace),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=5,
        state_store=store,
        workspace_root_identity=control.workspace_identity,
        control=control,
        pytest_process_isolation_enforced=True,
        pytest_external_egress_enforced=True,
    )
    return workspace, state, control, store, services


def test_live_internal_tool_refuses_out_of_band_workspace_drift(tmp_path: Path) -> None:
    workspace, state, control, store, services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint

    services.consume("inspect_repository", {})
    (workspace / "tracked.txt").write_text("outside-change\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="outside the authorized runtime mutation lineage"):
        services.consume("inspect_repository", {})

    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.expected_workspace_fingerprint == expected
    assert store.load().terminal_status is TerminalStatus.BLOCKED


def test_non_mutation_checkpoint_catches_drift_after_tool_entry(tmp_path: Path) -> None:
    workspace, state, control, _store, services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint

    services.consume("inspect_repository", {})
    (workspace / "tracked.txt").write_text("concurrent-change\n", encoding="utf-8")

    with pytest.raises(PermissionError, match="outside the authorized runtime mutation lineage"):
        services.checkpoint()

    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.expected_workspace_fingerprint == expected


def test_universal_pretool_denies_external_execution_after_workspace_drift(tmp_path: Path) -> None:
    workspace, state, control, store, services = _runtime(tmp_path)
    (workspace / "tracked.txt").write_text("external-pretool-drift\n", encoding="utf-8")

    result = pretool_policy_output(
        services.policy,
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {"issue_number": 42},
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert "outside the authorized runtime mutation lineage" in hook["permissionDecisionReason"]
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.budget.snapshot().tool_calls == 1
    assert control.budget.snapshot().network_calls == 0
    assert state.policy_decisions == []


def test_read_only_posttool_rejects_drift_and_never_rebases_authority(tmp_path: Path) -> None:
    workspace, state, control, store, services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint

    services.consume("inspect_repository", {})
    (workspace / "tracked.txt").write_text("return-gap-change\n", encoding="utf-8")

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__inspect_repository",
            "tool_input": {},
            "tool_response": {"content": [{"type": "text", "text": "observed"}]},
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert "workspace freshness changed" in hook["updatedToolOutput"]["error"]
    assert control.expected_workspace_fingerprint == expected
    assert state.terminal_status is TerminalStatus.BLOCKED


def test_external_posttool_sanitizes_remote_result_but_terminal_freshness_blocks_local_success(
    tmp_path: Path,
) -> None:
    workspace, state, control, store, services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint
    (workspace / "tracked.txt").write_text("external-return-drift\n", encoding="utf-8")

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {"issue_number": 42},
            "tool_response": {
                "content": [{"type": "text", "text": "untrusted provider result"}],
            },
        },
        state=state,
        evidence=services.evidence,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["content"][0]["text"] == "untrusted provider result"
    assert state.terminal_status is None
    assert state.mcp_status["github"] is MCPStatus.AVAILABLE
    assert len(state.external_evidence) == 1
    assert state.external_evidence[0] in state.evidence_ids
    assert control.expected_workspace_fingerprint == expected

    state.terminal_status = TerminalStatus.SUCCESS
    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.BLOCKED
    assert state.terminal_reason is not None
    assert "outside authorized mutation lineage" in state.terminal_reason
    assert control.expected_workspace_fingerprint == expected


def test_validation_posttool_drift_adds_not_verified_freshness_gate(tmp_path: Path) -> None:
    workspace, state, control, store, _services = _runtime(tmp_path)
    state.validation_results.append(
        ValidationResult(
            name="pytest",
            gate_id="pytest:full",
            revision=state.change_revision,
            status=ValidationStatus.PASS,
            summary="pytest passed before result acceptance",
            details={"scope": "regression", "args": []},
        )
    )
    (workspace / "tracked.txt").write_text("pytest-return-drift\n", encoding="utf-8")

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {"args": []},
            "tool_response": {"content": [{"type": "text", "text": "passed"}]},
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert state.terminal_status is TerminalStatus.BLOCKED
    freshness = state.validation_results[-1]
    assert freshness.name == "workspace_freshness"
    assert freshness.status is ValidationStatus.NOT_VERIFIED
    assert freshness.revision == state.change_revision
    assert freshness.details["scope"] == "post_execution_workspace_drift"
    assert freshness.details["tool_name"] == "mcp__qa__run_pytest"


def test_external_posttool_accepts_sanitized_result_when_workspace_is_fresh(tmp_path: Path) -> None:
    _workspace, state, control, store, services = _runtime(tmp_path)

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {"issue_number": 42},
            "tool_response": {
                "content": [{"type": "text", "text": "provider result"}],
            },
        },
        state=state,
        evidence=services.evidence,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["content"][0]["text"] == "provider result"
    assert state.terminal_status is None
    assert state.mcp_status["github"] is MCPStatus.AVAILABLE
    assert len(state.external_evidence) == 1
    assert state.external_evidence[0] in state.evidence_ids


def test_mutation_body_checkpoint_allows_authorized_candidate_transition(tmp_path: Path) -> None:
    workspace, state, control, _store, services = _runtime(tmp_path)
    relative = "tests/generated_test.py"
    control.prepare_mutation(relative, change_revision_before=state.change_revision)

    services.consume("create_test_file", {"path": relative, "source": "def test_ok():\n    assert True\n"})
    target = workspace / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("def test_ok():\n    assert True\n", encoding="utf-8")

    services.checkpoint()
    assert state.terminal_status is None
    assert control.pending_mutation is not None

    control.rollback_pending_mutation(reason="test cleanup")


def test_observer_marks_incomplete_fingerprint_non_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class IncompleteInspector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def snapshot(self) -> SimpleNamespace:
            return SimpleNamespace(
                fingerprint_complete=False,
                fingerprint="sha256:incomplete",
            )

    monkeypatch.setattr(workspace_freshness_module, "RepositoryInspector", IncompleteInspector)

    result = observe_workspace_freshness(
        tmp_path,
        expected_fingerprint="sha256:expected",
        expected_root_identity=None,
    )

    assert result.code is WorkspaceFreshnessCode.FINGERPRINT_INCOMPLETE
    assert result.fresh is False


def test_observer_marks_unavailable_subject_non_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnavailableInspector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("subject unavailable")

    monkeypatch.setattr(workspace_freshness_module, "RepositoryInspector", UnavailableInspector)

    result = observe_workspace_freshness(
        tmp_path,
        expected_fingerprint="sha256:expected",
        expected_root_identity=None,
    )

    assert result.code is WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE
    assert result.fresh is False


def test_terminal_success_remains_success_when_workspace_is_fresh(tmp_path: Path) -> None:
    workspace, state, control, _store, _services = _runtime(tmp_path)
    state.terminal_status = TerminalStatus.SUCCESS

    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.SUCCESS


def test_terminal_success_is_blocked_after_out_of_band_change(tmp_path: Path) -> None:
    workspace, state, control, _store, _services = _runtime(tmp_path)
    state.terminal_status = TerminalStatus.SUCCESS
    (workspace / "tracked.txt").write_text("late-outside-change\n", encoding="utf-8")

    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.BLOCKED
    assert state.terminal_reason is not None
    assert "outside authorized mutation lineage" in state.terminal_reason


def test_terminal_success_is_blocked_without_authorized_baseline(tmp_path: Path) -> None:
    workspace, state, control, _store, _services = _runtime(tmp_path)
    state.terminal_status = TerminalStatus.SUCCESS
    control.expected_workspace_fingerprint = None

    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.BLOCKED
    assert state.terminal_reason is not None
    assert "no authorized workspace fingerprint baseline" in state.terminal_reason


def test_terminal_success_becomes_not_verified_for_incomplete_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, state, control, _store, _services = _runtime(tmp_path)
    state.terminal_status = TerminalStatus.SUCCESS
    monkeypatch.setattr(
        agent_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.FINGERPRINT_INCOMPLETE,
            "incomplete",
        ),
    )

    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.NOT_VERIFIED
    assert state.terminal_reason is not None
    assert "fingerprint is incomplete" in state.terminal_reason


def test_terminal_success_becomes_infrastructure_failure_when_subject_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, state, control, _store, _services = _runtime(tmp_path)
    state.terminal_status = TerminalStatus.SUCCESS
    monkeypatch.setattr(
        agent_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE,
            "subject unavailable",
        ),
    )

    _enforce_terminal_workspace_freshness(state, control, workspace)

    assert state.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert state.terminal_reason is not None
    assert "subject identity could not be revalidated" in state.terminal_reason
