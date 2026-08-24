from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl, atomic_write_json


def make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-order"
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
        lease_id="lease-order",
    )


def test_prepare_journal_failure_clears_durable_pending_state_and_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    def fail_append(*_args: object, **_kwargs: object) -> str:
        raise OSError("journal unavailable")

    monkeypatch.setattr(control.journal, "append", fail_append)

    with pytest.raises(OSError, match="journal unavailable"):
        control.prepare_mutation("tests/test_checkout.py")

    assert control.pending_mutation is None
    metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pending_mutation"] is None
    rollback = control.metadata_path.parent / "rollback"
    assert not rollback.exists() or not list(rollback.iterdir())
    assert target.read_text(encoding="utf-8") == "before\n"


def test_commit_persistence_failure_preserves_pending_transaction_and_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("validated candidate\n", encoding="utf-8")

    monkeypatch.setattr(control, "persist", lambda: (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        control.commit_pending_mutation()

    assert control.pending_mutation is not None
    assert backup.is_file()
    assert target.read_text(encoding="utf-8") == "validated candidate\n"


def test_rollback_persistence_failure_keeps_backup_and_pending_after_bytes_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("candidate\n", encoding="utf-8")

    monkeypatch.setattr(control, "persist", lambda: (_ for _ in ()).throw(OSError("disk full")))

    with pytest.raises(OSError, match="disk full"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "before\n"
    assert control.pending_mutation is not None
    assert backup.is_file()


def test_commit_cleanup_failure_cannot_resurrect_pending_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("validated candidate\n", encoding="utf-8")

    monkeypatch.setattr(control, "_discard_backup_best_effort", lambda _backup: False)

    assert control.commit_pending_mutation() == "tests/test_checkout.py"

    assert control.pending_mutation is None
    metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pending_mutation"] is None
    assert backup.exists()
    assert target.read_text(encoding="utf-8") == "validated candidate\n"


def test_runtime_metadata_write_is_bounded_before_file_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "runtime.json"
    monkeypatch.setattr(run_control_module, "_MAX_RUNTIME_METADATA_BYTES", 10)

    with pytest.raises(ValueError, match="runtime metadata exceeds"):
        atomic_write_json(path, {"payload": "x" * 100})

    assert not path.exists()
