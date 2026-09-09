from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

import ai_qa_automation.runtime.runtime_hooks as runtime_hooks_module
from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_policy_output
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)
from ai_qa_automation.state import StateStore

_PRE_WORKSPACE_FINGERPRINT = "sha256:" + "1" * 64
_PRE_CONTEXT_FINGERPRINT = "sha256:" + "2" * 64
_CANDIDATE_WORKSPACE_FINGERPRINT = "sha256:" + "3" * 64


def _strict_pending_control(tmp_path: Path) -> tuple[RuntimeControl, str, Path, bytes]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_target.py"
    target = workspace / relative_path
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
        lease_id="lease-mutation-commit-freshness",
        expected_workspace_fingerprint=_PRE_WORKSPACE_FINGERPRINT,
    )
    control.prepare_mutation(
        relative_path,
        change_revision_before=0,
        candidate_required=True,
        pre_mutation_context_fingerprint=_PRE_CONTEXT_FINGERPRINT,
    )
    candidate = b"def test_target():\n    assert 1 == 1\n"
    target.write_bytes(candidate)
    control.bind_pending_mutation_candidate(
        relative_path,
        hashlib.sha256(candidate).hexdigest(),
        candidate_workspace_fingerprint=_CANDIDATE_WORKSPACE_FINGERPRINT,
    )
    control.set_workspace_fingerprint(_CANDIDATE_WORKSPACE_FINGERPRINT)
    return control, relative_path, target, candidate


def test_commit_reproves_candidate_workspace_after_canonical_closure_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, relative_path, target, candidate = _strict_pending_control(tmp_path)
    state = AgentRunState(
        objective="reject close-time workspace drift",
        workspace=str(control.workspace),
        change_revision=1,
    )
    state_store = StateStore(control.metadata_path.parent / "state.json")
    state_store.save(state)

    observations = iter(
        [
            WorkspaceFreshness(WorkspaceFreshnessCode.FRESH, "fresh after pytest"),
            WorkspaceFreshness(
                WorkspaceFreshnessCode.WORKSPACE_DRIFT,
                "drift before mutation commit",
            ),
        ]
    )
    monkeypatch.setattr(
        runtime_hooks_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: next(observations),
    )
    monkeypatch.setattr(
        runtime_hooks_module,
        "_bind_latest_targeted_pytest_to_pending_mutation",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        runtime_hooks_module,
        "evaluate_revision_closure",
        lambda *_args, **_kwargs: SimpleNamespace(closed=True),
    )

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__run_pytest",
            "tool_input": {"args": [relative_path]},
            "tool_response": {"is_error": False},
        },
        state=state,
        state_store=state_store,
        control=control,
    )

    assert result["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True
    assert "workspace freshness changed before commit" in result["hookSpecificOutput"][
        "updatedToolOutput"
    ]["error"]
    assert control.pending_mutation is not None
    assert control.pending_mutation.relative_path == relative_path
    assert target.read_bytes() == candidate
    assert "mcp__qa__apply_locator_heal" in control.open_circuits
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert any(
        item.name == "workspace_freshness"
        and item.status is ValidationStatus.NOT_VERIFIED
        and item.revision == state.change_revision
        for item in state.validation_results
    )
    assert '"stage":"mutation_commit"' in control.journal.path.read_text(encoding="utf-8")

    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert any(
        item.name == "workspace_freshness" and item.status is ValidationStatus.NOT_VERIFIED
        for item in persisted.validation_results
    )
