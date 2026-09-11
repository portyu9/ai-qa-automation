from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

from ai_qa_automation.agent import (
    _TerminalJournalAudit,
    _finish_terminal_state,
    _persist_terminal_state,
)
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def _terminal_subject(
    tmp_path: Path,
) -> tuple[AgentRunState, StateStore, RunJournal, RuntimeControl]:
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
    return state, state_store, journal, control


def test_final_runtime_persistence_failure_supersedes_prior_finished_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, state_store, journal, control = _terminal_subject(tmp_path)
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
        audit=_TerminalJournalAudit(journal),
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
        for line in journal.path.read_text(encoding="utf-8").splitlines()
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


def test_terminal_correction_journal_ambiguity_is_not_replayed_and_is_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, state_store, journal, control = _terminal_subject(tmp_path)
    persist_attempts = 0
    correction_attempts = 0
    original_try_append = RunJournal.try_append

    def fail_final_runtime_persist() -> None:
        nonlocal persist_attempts
        persist_attempts += 1
        raise OSError("post-write runtime identity is ambiguous")

    def fail_correction_append(
        self: RunJournal,
        event: str,
        **payload: object,
    ) -> bool:
        nonlocal correction_attempts
        if self is journal and event == "terminal_runtime_metadata_persistence_failed":
            correction_attempts += 1
            raise OSError("post-fsync correction journal identity is ambiguous")
        return original_try_append(self, event, **payload)

    monkeypatch.setattr(control, "persist", fail_final_runtime_persist)
    monkeypatch.setattr(RunJournal, "try_append", fail_correction_append)
    audit = _TerminalJournalAudit(journal)

    _finish_terminal_state(
        state=state,
        state_store=state_store,
        control=control,
        audit=audit,
        logger=logging.getLogger("terminal-persistence-correction-ambiguity-test"),
        started=time.monotonic(),
    )

    assert persist_attempts == 1
    assert correction_attempts == 1
    assert audit.failure_event == "terminal_runtime_metadata_persistence_failed"
    assert audit.failure_type == "OSError"

    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    assert "terminal journal persistence could not be guaranteed" in (
        persisted.terminal_reason or ""
    ).lower()
    assert "terminal_runtime_metadata_persistence_failed" in (
        persisted.terminal_reason or ""
    )

    records = [
        json.loads(line)
        for line in journal.path.read_text(encoding="utf-8").splitlines()
    ]
    assert [record["event"] for record in records] == ["agent_run_finished"]
    assert records[0]["payload"]["terminal_status"] == TerminalStatus.SUCCESS.value
    assert journal.verify()["valid"] is True


def test_runtime_persistence_failure_without_finish_event_has_no_supersession_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, state_store, journal, control = _terminal_subject(tmp_path)
    state.terminal_status = TerminalStatus.BLOCKED
    state.terminal_reason = "Workspace lease could not be acquired."
    persist_attempts = 0

    def fail_runtime_persist() -> None:
        nonlocal persist_attempts
        persist_attempts += 1
        raise OSError("post-write runtime identity is ambiguous")

    monkeypatch.setattr(control, "persist", fail_runtime_persist)

    _persist_terminal_state(
        state,
        state_store,
        control,
        _TerminalJournalAudit(journal),
    )

    assert persist_attempts == 1
    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    records = [
        json.loads(line)
        for line in journal.path.read_text(encoding="utf-8").splitlines()
    ]
    assert [record["event"] for record in records] == [
        "terminal_runtime_metadata_persistence_failed"
    ]
    correction = records[0]["payload"]
    assert correction["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert correction["error_type"] == "OSError"
    assert "supersedes_event" not in correction
    assert journal.verify()["valid"] is True
