from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

from ai_qa_automation.agent import _TerminalJournalAudit, _finish_terminal_state
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def test_final_runtime_persistence_failure_supersedes_prior_finished_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(
        run_id="run-terminal-persistence",
        objective="preserve coherent terminal persistence truth",
        workspace=str(workspace),
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
        lease_id="terminal-persistence-test",
    )
    control.persist()
    audit = _TerminalJournalAudit(journal)
    persist_attempts = 0

    def fail_final_runtime_persist() -> None:
        nonlocal persist_attempts
        persist_attempts += 1
        raise OSError("post-write runtime identity is ambiguous")

    monkeypatch.setattr(control, "persist", fail_final_runtime_persist)

    _finish_terminal_state(
        state=state,
        state_store=state_store,
        control=control,
        audit=audit,
        logger=logging.getLogger("terminal-persistence-coherence-test"),
        started=time.monotonic(),
    )

    assert persist_attempts == 1
    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert "runtime metadata persistence could not be guaranteed" in (
        persisted.terminal_reason or ""
    ).lower()

    records = [
        json.loads(line)
        for line in (run_dir / "journal.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [record["event"] for record in records] == [
        "agent_run_finished",
        "terminal_runtime_metadata_persistence_failed",
    ]
    assert records[0]["payload"]["terminal_status"] == TerminalStatus.SUCCESS.value
    correction = records[1]["payload"]
    assert correction["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert correction["supersedes_event"] == "agent_run_finished"
    assert correction["error_type"] == "OSError"
    assert journal.verify()["valid"] is True
