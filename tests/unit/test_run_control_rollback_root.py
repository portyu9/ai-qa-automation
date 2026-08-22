from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import MutationPendingError, RuntimeControl


def control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-1"
    return RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=20,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-1",
    )


def test_prepare_mutation_rejects_symlinked_rollback_directory(tmp_path: Path) -> None:
    subject = control(tmp_path)
    target = subject.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    outside = tmp_path / "outside-rollback"
    outside.mkdir()
    rollback = subject.metadata_path.parent / "rollback"
    rollback.parent.mkdir(parents=True, exist_ok=True)
    try:
        rollback.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(MutationPendingError, match="rollback directory.*symlink"):
        subject.prepare_mutation("tests/test_checkout.py")

    assert subject.pending_mutation is None
    assert list(outside.iterdir()) == []


def test_existing_transaction_rejects_rollback_directory_replaced_by_symlink(
    tmp_path: Path,
) -> None:
    subject = control(tmp_path)
    target = subject.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    subject.prepare_mutation("tests/test_checkout.py")
    assert subject.pending_mutation is not None

    rollback = subject.metadata_path.parent / "rollback"
    backup = Path(str(subject.pending_mutation.backup_path))
    backup_bytes = backup.read_bytes()
    backup.unlink()
    rollback.rmdir()
    outside = tmp_path / "outside-rollback"
    outside.mkdir()
    (outside / backup.name).write_bytes(backup_bytes)
    try:
        rollback.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    target.write_text("candidate\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="rollback directory.*symlink"):
        subject.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert subject.pending_mutation is not None
