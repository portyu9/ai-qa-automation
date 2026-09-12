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


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact canonical-state publication reconciliation requires descriptor-relative authority"
        )


def test_published_terminal_state_write_is_reconciled_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()

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


def test_unpublished_state_write_failure_is_not_reconciled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()

    state_path = tmp_path / "run" / "state.json"
    store = StateStore(state_path)
    original = AgentRunState(objective="original", workspace=str(tmp_path))
    store.save(original)

    def fail_before_publication(*_args: object, **_kwargs: object) -> None:
        raise OSError("canonical state write failed before publication")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", fail_before_publication)
    updated = original.model_copy(update={"objective": "updated"})

    with pytest.raises(OSError, match="before publication"):
        store.save(updated)

    assert store.load().objective == "original"


def test_create_only_initial_publication_ambiguity_is_not_adopted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()

    state_path = tmp_path / "artifacts" / "run" / "state.json"
    store = StateStore(state_path, claim_parent_exclusively=True)
    state = AgentRunState(objective="initial authority", workspace=str(tmp_path))
    original_atomic_write = state_module.atomic_write_bytes_confined
    write_attempts = 0

    def publish_initial_then_raise(*args: object, **kwargs: object) -> None:
        nonlocal write_attempts
        write_attempts += 1
        original_atomic_write(*args, **kwargs)
        raise OSError("initial canonical state publication became ambiguous")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_initial_then_raise)

    with pytest.raises(OSError, match="initial canonical state publication"):
        store.save(state)

    assert write_attempts == 1
    assert state_path.is_file()

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", original_atomic_write)
    with pytest.raises(FileExistsError):
        store.save(state)


def test_reconciliation_requires_fresh_directory_durability_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()

    state_path = tmp_path / "run" / "state.json"
    store = StateStore(state_path)
    original = AgentRunState(objective="original", workspace=str(tmp_path))
    store.save(original)
    original_atomic_write = state_module.atomic_write_bytes_confined

    def publish_then_break_reconciliation(*args: object, **kwargs: object) -> None:
        original_atomic_write(*args, **kwargs)

        def fail_fsync(_fd: int) -> None:
            raise OSError("reconciliation directory fsync failed")

        monkeypatch.setattr(state_module.os, "fsync", fail_fsync)
        raise OSError("post-publication canonical state verification became ambiguous")

    monkeypatch.setattr(
        state_module,
        "atomic_write_bytes_confined",
        publish_then_break_reconciliation,
    )
    updated = original.model_copy(update={"objective": "updated"})

    with pytest.raises(OSError, match="post-publication"):
        store.save(updated)


def test_reconciliation_rejects_state_changed_between_exact_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()

    state_path = tmp_path / "run" / "state.json"
    store = StateStore(state_path)
    original = AgentRunState(objective="original", workspace=str(tmp_path))
    store.save(original)
    original_atomic_write = state_module.atomic_write_bytes_confined
    original_read = state_module.read_bytes_confined
    reconciliation_reads = 0

    def publish_then_install_racing_reader(*args: object, **kwargs: object) -> None:
        original_atomic_write(*args, **kwargs)

        def racing_read(*read_args: object, **read_kwargs: object) -> bytes:
            nonlocal reconciliation_reads
            reconciliation_reads += 1
            if reconciliation_reads == 2:
                state_path.write_bytes(b"{}")
            return original_read(*read_args, **read_kwargs)

        monkeypatch.setattr(state_module, "read_bytes_confined", racing_read)
        raise OSError("post-publication canonical state verification became ambiguous")

    monkeypatch.setattr(
        state_module,
        "atomic_write_bytes_confined",
        publish_then_install_racing_reader,
    )
    updated = original.model_copy(update={"objective": "updated"})

    with pytest.raises(OSError, match="post-publication"):
        store.save(updated)

    assert reconciliation_reads == 2
