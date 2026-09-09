from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_failure_output, posttool_policy_output
from ai_qa_automation.state import StateStore

_PRE_WORKSPACE_FINGERPRINT = "sha256:" + "1" * 64
_PRE_CONTEXT_FINGERPRINT = "sha256:" + "2" * 64
_TOOL = "mcp__qa__apply_locator_heal"


def _ambiguous_failed_mutation(
    tmp_path: Path,
) -> tuple[RuntimeControl, AgentRunState, StateStore, str, Path, bytes]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    relative = "tests/test_target.py"
    target = workspace / relative
    target.parent.mkdir(parents=True)
    target.write_bytes(b"def test_target():\n    assert True\n")
    run_dir = tmp_path / "run"
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
        lease_id="lease-mutation-failure-rollback-truth",
        expected_workspace_fingerprint=_PRE_WORKSPACE_FINGERPRINT,
    )
    control.prepare_mutation(
        relative,
        change_revision_before=0,
        candidate_required=True,
        pre_mutation_context_fingerprint=_PRE_CONTEXT_FINGERPRINT,
    )
    independent = b"def test_target():\n    assert 'independent writer'\n"
    target.write_bytes(independent)
    state = AgentRunState(
        objective="preserve failed mutation ambiguity as blocked truth",
        workspace=str(workspace),
        target_git_sha="a" * 40,
    )
    store = StateStore(run_dir / "state.json")
    store.save(state)
    return control, state, store, relative, target, independent


def _assert_blocked_preserved(
    control: RuntimeControl,
    state: AgentRunState,
    store: StateStore,
    relative: str,
    target: Path,
    independent: bytes,
) -> None:
    assert target.read_bytes() == independent
    assert control.pending_mutation is not None
    assert control.pending_mutation.relative_path == relative
    assert control.pending_mutation.candidate_sha256 is None
    assert _TOOL in control.open_circuits
    assert state.terminal_status is TerminalStatus.BLOCKED
    persisted = store.load()
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert persisted.terminal_reason is not None
    assert "rollback" in persisted.terminal_reason.lower()


def test_error_shaped_mutation_response_normalizes_unsafe_rollback_refusal(
    tmp_path: Path,
) -> None:
    control, state, store, relative, target, independent = _ambiguous_failed_mutation(tmp_path)

    result = posttool_policy_output(
        {
            "tool_name": _TOOL,
            "tool_input": {"proposal_evidence_id": "proposal"},
            "tool_response": {"is_error": True, "content": []},
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert isinstance(hook, dict)
    updated = hook["updatedToolOutput"]
    assert isinstance(updated, dict)
    assert updated["is_error"] is True
    assert "rollback" in str(updated["error"]).lower()
    _assert_blocked_preserved(control, state, store, relative, target, independent)


def test_failure_hook_normalizes_unsafe_rollback_refusal(tmp_path: Path) -> None:
    control, state, store, relative, target, independent = _ambiguous_failed_mutation(tmp_path)

    result = posttool_failure_output(
        {
            "tool_name": _TOOL,
            "tool_input": {"proposal_evidence_id": "proposal"},
            "error": "publisher failed",
        },
        state=state,
        state_store=store,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert isinstance(hook, dict)
    assert "rollback" in str(hook["additionalContext"]).lower()
    _assert_blocked_preserved(control, state, store, relative, target, independent)


def test_rollback_refusal_is_durable_before_later_failure_hook_bookkeeping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, state, store, relative, target, independent = _ambiguous_failed_mutation(tmp_path)

    def fail_later_bookkeeping(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("later hook bookkeeping failed")

    monkeypatch.setattr(control, "record_tool_result", fail_later_bookkeeping)

    with pytest.raises(RuntimeError, match="later hook bookkeeping failed"):
        posttool_failure_output(
            {
                "tool_name": _TOOL,
                "tool_input": {"proposal_evidence_id": "proposal"},
                "error": "publisher failed",
            },
            state=state,
            state_store=store,
            control=control,
        )

    assert target.read_bytes() == independent
    persisted = store.load()
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert persisted.terminal_reason is not None
    assert "rollback" in persisted.terminal_reason.lower()

    runtime = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    pending = runtime["pending_mutation"]
    assert isinstance(pending, dict)
    assert pending["relative_path"] == relative
    assert pending["candidate_required"] is True
    assert pending["candidate_sha256"] is None
    assert _TOOL in runtime["open_circuits"]
