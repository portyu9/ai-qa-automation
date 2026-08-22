from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import (
    CircuitOpenError,
    MutationPendingError,
    RuntimeControl,
)


def make_control(tmp_path: Path, *, threshold: int = 3) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir(exist_ok=True)
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
        circuit_failure_threshold=threshold,
    )


def test_tool_circuit_opens_after_threshold_and_success_resets(tmp_path: Path) -> None:
    control = make_control(tmp_path, threshold=2)

    control.before_tool("github")
    control.record_tool_result("github", failed=True)
    control.before_tool("github")
    control.record_tool_result("github", failed=True)

    with pytest.raises(CircuitOpenError, match="github"):
        control.before_tool("github")

    control.record_tool_result("github", failed=False)
    control.before_tool("github")
    assert "github" not in control.open_circuits
    assert "github" not in control.circuit_failures


def test_existing_file_mutation_rolls_back_transactionally(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    assert control.pending_mutation.existed is True
    assert control.pending_mutation.backup_path is not None
    target.write_text("after\n", encoding="utf-8")

    restored = control.rollback_pending_mutation(reason="validation failed")

    assert restored == "tests/test_checkout.py"
    assert target.read_text(encoding="utf-8") == "before\n"
    assert control.pending_mutation is None
    metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pending_mutation"] is None
    assert control.journal.verify()["valid"] is True


def test_new_file_mutation_rollback_removes_unverified_file(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_generated.py"

    control.prepare_mutation("tests/test_generated.py")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("def test_generated():\n    assert True\n", encoding="utf-8")

    control.rollback_pending_mutation(reason="regression not verified")

    assert not target.exists()
    assert control.pending_mutation is None


def test_committed_mutation_discards_rollback_snapshot_and_keeps_change(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")

    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("validated change\n", encoding="utf-8")

    committed = control.commit_pending_mutation()

    assert committed == "tests/test_checkout.py"
    assert target.read_text(encoding="utf-8") == "validated change\n"
    assert not backup.exists()
    assert control.pending_mutation is None


def test_second_or_escaping_mutation_is_denied(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    control.prepare_mutation("tests/test_one.py")

    with pytest.raises(MutationPendingError, match="already pending"):
        control.prepare_mutation("tests/test_two.py")

    control.rollback_pending_mutation(reason="cleanup")
    with pytest.raises(MutationPendingError, match="escapes"):
        control.prepare_mutation("../outside.py")
