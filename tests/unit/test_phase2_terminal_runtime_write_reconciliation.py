from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import pytest

import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.agent import _finish_terminal_state, _TerminalJournalAudit
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def _terminal_subject(
    tmp_path: Path,
) -> tuple[AgentRunState, StateStore, RunJournal, RuntimeControl]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(
        run_id=run_dir.name,
        objective="reconcile exact terminal runtime publication",
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
        lease_id="terminal-runtime-reconciliation-test",
    )
    control.persist()
    return state, state_store, journal, control


def _publish_then_raise(
    original_write: object,
    attempt_counter: list[int],
):
    def wrapped(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        attempt_counter[0] += 1
        assert callable(original_write)
        original_write(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("post-publication runtime verification became ambiguous")

    return wrapped


def test_published_terminal_runtime_write_is_reconciled_before_correction_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact runtime publication reconciliation requires descriptor-relative authority"
        )

    state, state_store, journal, control = _terminal_subject(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined
    original_try_append = RunJournal.try_append
    original_state_save = state_store.save
    persist_attempts = [0]
    correction_attempts = 0
    state_save_attempts = 0

    monkeypatch.setattr(
        run_control_module,
        "atomic_write_bytes_confined",
        _publish_then_raise(original_atomic_write, persist_attempts),
    )

    def reject_any_correction_append(
        self: RunJournal,
        event: str,
        **payload: object,
    ) -> bool:
        nonlocal correction_attempts
        if self is journal and event == "terminal_runtime_metadata_persistence_failed":
            correction_attempts += 1
            raise OSError("correction append must be unreachable after exact runtime proof")
        return original_try_append(self, event, **payload)

    def reject_any_second_terminal_state_save(observed_state: AgentRunState) -> None:
        nonlocal state_save_attempts
        state_save_attempts += 1
        if state_save_attempts > 1:
            raise OSError(
                "second terminal state save must be unreachable after exact runtime proof"
            )
        original_state_save(observed_state)

    monkeypatch.setattr(RunJournal, "try_append", reject_any_correction_append)
    monkeypatch.setattr(state_store, "save", reject_any_second_terminal_state_save)

    _finish_terminal_state(
        state=state,
        state_store=state_store,
        control=control,
        audit=_TerminalJournalAudit(journal),
        logger=logging.getLogger("terminal-runtime-reconciliation-test"),
        started=time.monotonic(),
    )

    assert persist_attempts == [1]
    assert correction_attempts == 0
    assert state_save_attempts == 1

    persisted = state_store.load()
    assert persisted.terminal_status is TerminalStatus.SUCCESS
    records = [json.loads(line) for line in journal.path.read_text(encoding="utf-8").splitlines()]
    assert [record["event"] for record in records] == ["agent_run_finished"]
    assert records[0]["payload"]["terminal_status"] == TerminalStatus.SUCCESS.value

    recovery = inspect_recovery(journal.path.parent)
    assert recovery["recoverable"] is True
    assert recovery["terminal_status"] == TerminalStatus.SUCCESS.value
    assert recovery["revision_closed"] is True
    assert recovery["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"


def test_prepublication_runtime_failure_is_not_reconciled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact runtime publication reconciliation requires descriptor-relative authority"
        )

    _, _, _, control = _terminal_subject(tmp_path)

    def fail_before_publication(*args: object, **kwargs: object) -> None:
        raise OSError("runtime publication did not occur")

    monkeypatch.setattr(
        run_control_module,
        "atomic_write_bytes_confined",
        fail_before_publication,
    )

    with pytest.raises(OSError, match="runtime publication did not occur"):
        control.persist()


def test_reconciled_runtime_publication_requires_fresh_directory_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact runtime publication reconciliation requires descriptor-relative authority"
        )

    _, _, _, control = _terminal_subject(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined

    def publish_then_disable_fsync(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        original_atomic_write(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )

        def fail_fsync(fd: int) -> None:
            raise OSError("fresh directory durability barrier failed")

        monkeypatch.setattr(run_control_module.os, "fsync", fail_fsync)
        raise OSError("post-publication runtime verification became ambiguous")

    monkeypatch.setattr(
        run_control_module,
        "atomic_write_bytes_confined",
        publish_then_disable_fsync,
    )

    with pytest.raises(OSError, match="post-publication runtime verification became ambiguous"):
        control.persist()


def test_reconciliation_rejects_wrong_published_runtime_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "exact runtime publication reconciliation requires descriptor-relative authority"
        )

    _, _, _, control = _terminal_subject(tmp_path)
    original_atomic_write = run_control_module.atomic_write_bytes_confined

    def publish_wrong_bytes_then_raise(
        root: Path,
        relative_path: str | Path,
        data: bytes,
        *,
        create_parents: bool,
        create_only: bool,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        original_atomic_write(
            root,
            relative_path,
            data + b"\n",
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("post-publication runtime verification became ambiguous")

    monkeypatch.setattr(
        run_control_module,
        "atomic_write_bytes_confined",
        publish_wrong_bytes_then_raise,
    )

    with pytest.raises(OSError, match="post-publication runtime verification became ambiguous"):
        control.persist()
