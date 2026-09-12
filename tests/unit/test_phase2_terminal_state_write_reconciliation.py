from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

import ai_qa_automation.state as state_module
from ai_qa_automation.agent import _finish_terminal_state, _TerminalJournalAudit
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def test_published_terminal_state_write_is_reconciled_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact canonical-state publication reconciliation requires descriptor-relative authority"
        )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(
        run_id=run_dir.name,
        objective="reconcile exact terminal canonical-state publication",
        workspace=str(workspace.resolve()),
        phase="RUNNING",
        terminal_status=TerminalStatus.SUCCESS,
        terminal_reason="Deterministic validation proved success.",
    )
    state_store = StateStore(run_dir / "state.json")
    state_store.save(state)
    journal = RunJournal(run_dir / "journal.jsonl")
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=5,
            max_network_calls=2,
            max_mutations=1,
            max_wall_seconds=60,
        ),
        journal=journal,
        metadata_path=run_dir / "runtime.json",
        lease_id="terminal-state-reconciliation-test",
    )
    control.persist()

    original_atomic_write = state_module.atomic_write_bytes_confined
    write_attempts = 0

    def publish_state_then_raise(*args: object, **kwargs: object) -> None:
        nonlocal write_attempts
        write_attempts += 1
        original_atomic_write(*args, **kwargs)
        raise OSError("post-publication canonical state verification became ambiguous")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_state_then_raise)

    _finish_terminal_state(
        state=state,
        state_store=state_store,
        control=control,
        audit=_TerminalJournalAudit(journal),
        logger=logging.getLogger("terminal-state-reconciliation-test"),
        started=time.monotonic(),
    )

    assert write_attempts == 1
    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.SUCCESS
    assert persisted.terminal_reason == "Deterministic validation proved success."

    records = [json.loads(line) for line in journal.path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == ["agent_run_finished"]
    assert records[0]["payload"]["terminal_status"] == TerminalStatus.SUCCESS.value

    recovery = inspect_recovery(run_dir)
    assert recovery["recoverable"] is True
    assert recovery["terminal_status"] == TerminalStatus.SUCCESS.value
    assert recovery["revision_closed"] is True
    assert recovery["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"
