from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.live_services as live_services_module
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import (
    posttool_failure_output,
    posttool_policy_output,
)
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)
from ai_qa_automation.state import StateStore


def _runtime(
    tmp_path: Path,
) -> tuple[AgentRunState, RuntimeControl, StateStore, LiveRuntimeServices]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(
        objective="bind mutation ownership to a fresh workspace",
        workspace=str(workspace),
        target_git_sha="a" * 40,
    )
    store = StateStore(run_dir / "state.json")
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=5,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-workspace-mutation-freshness",
    )
    control.set_workspace_fingerprint("sha256:authorized-baseline")
    store.save(state)
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=PolicyEngine(tmp_path / "control", workspace, allow_test_writes=True),
        test_runner=cast(Any, object()),
        max_tool_calls=10,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=control.workspace_identity,
        control=control,
    )
    return state, control, store, services


def test_freshness_denied_mutation_failure_does_not_rebase_workspace_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, control, store, services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint
    monkeypatch.setattr(
        live_services_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.WORKSPACE_DRIFT,
            "drift",
        ),
    )

    with pytest.raises(PermissionError, match="outside the authorized runtime mutation lineage"):
        services.consume(
            "create_test_file",
            {"path": "tests/test_generated.py", "source": "def test_ok():\n    assert True\n"},
        )

    assert control.pending_mutation is None
    assert control.expected_workspace_fingerprint == expected

    posttool_failure_output(
        {
            "tool_name": "mcp__qa__create_test_file",
            "tool_input": {"path": "tests/test_generated.py"},
            "error": "workspace freshness denied before mutation preparation",
        },
        state=state,
        state_store=store,
        control=control,
    )

    assert control.pending_mutation is None
    assert control.expected_workspace_fingerprint == expected
    assert state.terminal_status is TerminalStatus.BLOCKED


def test_mutation_success_without_pending_transaction_is_rejected_without_rebase(
    tmp_path: Path,
) -> None:
    state, control, store, _services = _runtime(tmp_path)
    expected = control.expected_workspace_fingerprint

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__create_test_file",
            "tool_input": {"path": "tests/test_generated.py"},
            "tool_response": {"path": "tests/test_generated.py"},
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert "transaction authority was not prepared" in hook["updatedToolOutput"]["error"]
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.pending_mutation is None
    assert control.expected_workspace_fingerprint == expected
    assert "mcp__qa__create_test_file" in control.open_circuits
    assert "mcp__qa__apply_locator_heal" in control.open_circuits
