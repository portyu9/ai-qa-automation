from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal, validate_runtime_journal_binding
from ai_qa_automation.runtime.run_control import RuntimeControl


def _make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-journal-binding"
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=20,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-journal-binding",
    )


def _runtime_metadata(control: RuntimeControl) -> dict[str, object]:
    raw = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def _assert_exact_journal_binding(control: RuntimeControl) -> None:
    binding = validate_runtime_journal_binding(
        _runtime_metadata(control),
        control.journal.verify(),
    )
    assert binding["valid"] is True
    assert binding["events"] == control.journal.event_count
    assert binding["head_hash"] == control.journal.head_hash


def test_successful_prepare_returns_with_exact_runtime_journal_binding(tmp_path: Path) -> None:
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    control.prepare_mutation("tests/test_checkout.py", change_revision_before=7)

    assert control.pending_mutation is not None
    _assert_exact_journal_binding(control)


def test_successful_commit_returns_with_exact_runtime_journal_binding(tmp_path: Path) -> None:
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    target.write_text("validated candidate\n", encoding="utf-8")

    assert control.commit_pending_mutation() == "tests/test_checkout.py"

    assert control.pending_mutation is None
    _assert_exact_journal_binding(control)


def test_successful_rollback_returns_with_exact_runtime_journal_binding(tmp_path: Path) -> None:
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    target.write_text("candidate\n", encoding="utf-8")

    assert control.rollback_pending_mutation(reason="validation failed") == "tests/test_checkout.py"

    assert target.read_text(encoding="utf-8") == "before\n"
    assert control.pending_mutation is None
    _assert_exact_journal_binding(control)


def test_ambiguous_post_fsync_commit_journal_failure_cannot_return_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    target.write_text("validated candidate\n", encoding="utf-8")
    original_append = control.journal.append

    def append_then_fail(event: str, **payload: object) -> str:
        record_hash = original_append(event, **payload)
        if event == "mutation_committed":
            raise OSError("post-fsync journal identity became ambiguous")
        return record_hash

    monkeypatch.setattr(control.journal, "append", append_then_fail)

    with pytest.raises(
        RuntimeError,
        match="mutation transition journal persistence could not be guaranteed",
    ):
        control.commit_pending_mutation()

    assert target.read_text(encoding="utf-8") == "validated candidate\n"
    assert control.pending_mutation is None
    binding = validate_runtime_journal_binding(
        _runtime_metadata(control),
        control.journal.verify(),
    )
    assert binding["valid"] is False
    assert binding["reason"] == "runtime journal authority does not match persisted journal"


def test_post_event_runtime_rebind_failure_cannot_return_commit_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    target.write_text("validated candidate\n", encoding="utf-8")
    original_persist = control.persist
    persist_calls = 0

    def fail_second_persist() -> None:
        nonlocal persist_calls
        persist_calls += 1
        if persist_calls == 2:
            raise OSError("runtime metadata unavailable after journal append")
        original_persist()

    monkeypatch.setattr(control, "persist", fail_second_persist)

    with pytest.raises(
        RuntimeError,
        match="mutation transition journal binding could not be durably persisted",
    ):
        control.commit_pending_mutation()

    assert persist_calls == 2
    assert target.read_text(encoding="utf-8") == "validated candidate\n"
    assert control.pending_mutation is None
    binding = validate_runtime_journal_binding(
        _runtime_metadata(control),
        control.journal.verify(),
    )
    assert binding["valid"] is False
