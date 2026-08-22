from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import (
    CircuitOpenError,
    MutationPendingError,
    PendingMutation,
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


def test_circuit_failures_are_isolated_per_tool(tmp_path: Path) -> None:
    control = make_control(tmp_path, threshold=2)
    control.record_tool_result("github", failed=True)
    control.record_tool_result("github", failed=True)

    with pytest.raises(CircuitOpenError):
        control.before_tool("github")
    control.before_tool("pytest")
    assert "pytest" not in control.open_circuits


@pytest.mark.parametrize("threshold", [0, -1, True])
def test_circuit_failure_threshold_must_be_positive_integer(
    tmp_path: Path, threshold: object
) -> None:
    with pytest.raises(ValueError, match="circuit_failure_threshold"):
        make_control(tmp_path, threshold=threshold)  # type: ignore[arg-type]


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


def test_committed_mutation_discards_verified_rollback_snapshot_and_keeps_change(
    tmp_path: Path,
) -> None:
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


def test_tampered_rollback_backup_blocks_commit_and_preserves_pending_transaction(
    tmp_path: Path,
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("candidate\n", encoding="utf-8")
    backup.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="integrity"):
        control.commit_pending_mutation()

    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert control.pending_mutation is not None


def test_missing_rollback_backup_blocks_commit(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    Path(str(control.pending_mutation.backup_path)).unlink()
    target.write_text("candidate\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="missing or not a regular file"):
        control.commit_pending_mutation()

    assert target.read_text(encoding="utf-8") == "candidate\n"
    assert control.pending_mutation is not None


def test_second_or_escaping_mutation_is_denied(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    control.prepare_mutation("tests/test_one.py")

    with pytest.raises(MutationPendingError, match="already pending"):
        control.prepare_mutation("tests/test_two.py")

    control.rollback_pending_mutation(reason="cleanup")
    with pytest.raises(MutationPendingError, match="escapes"):
        control.prepare_mutation("../outside.py")


def test_symlink_escape_cannot_be_used_as_mutation_path(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = control.workspace / "tests"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(MutationPendingError, match="symlink"):
        control.prepare_mutation("tests/test_escape.py")

    assert control.pending_mutation is None
    assert not (outside / "test_escape.py").exists()


def test_existing_symlink_target_is_rejected_even_when_link_stays_inside_workspace(
    tmp_path: Path,
) -> None:
    control = make_control(tmp_path)
    real = control.workspace / "tests" / "real.py"
    real.parent.mkdir(parents=True)
    real.write_text("assert True\n", encoding="utf-8")
    link = control.workspace / "tests" / "linked.py"
    try:
        link.symlink_to(real)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(MutationPendingError, match="symlink"):
        control.prepare_mutation("tests/linked.py")

    assert control.pending_mutation is None


def test_existing_directory_is_not_a_valid_mutation_target(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "directory.py"
    target.mkdir(parents=True)

    with pytest.raises(MutationPendingError, match="regular file"):
        control.prepare_mutation("tests/directory.py")


def test_oversized_existing_file_is_refused_before_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "large.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"x" * 2_000_001)
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path == target:
            raise AssertionError("oversized mutation target must not be read before size rejection")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    with pytest.raises(MutationPendingError, match="2 MB"):
        control.prepare_mutation("tests/large.py")

    assert control.pending_mutation is None
    rollback_dir = control.metadata_path.parent / "rollback"
    assert not rollback_dir.exists() or not any(rollback_dir.iterdir())


def test_tampered_rollback_backup_blocks_restore_and_preserves_pending_transaction(
    tmp_path: Path,
) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("after\n", encoding="utf-8")
    backup.write_text("attacker-controlled\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="integrity"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "after\n"
    assert control.pending_mutation is not None


def test_oversized_rollback_backup_is_rejected_before_restore(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    target.write_text("after\n", encoding="utf-8")
    backup.write_bytes(b"x" * 2_000_001)

    with pytest.raises(RuntimeError, match="2 MB"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "after\n"
    assert control.pending_mutation is not None


def test_missing_rollback_backup_blocks_restore(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    backup = Path(str(control.pending_mutation.backup_path))
    backup.unlink()
    target.write_text("after\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="missing or not a regular file"):
        control.rollback_pending_mutation(reason="validation failed")

    assert target.read_text(encoding="utf-8") == "after\n"
    assert control.pending_mutation is not None


def test_rollback_backup_path_is_confined_to_runtime_rollback_directory(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    original = control.pending_mutation

    outside_backup = tmp_path / "attacker.bin"
    outside_backup.write_text("before\n", encoding="utf-8")
    control.pending_mutation = PendingMutation(
        relative_path=original.relative_path,
        existed=True,
        backup_path=str(outside_backup),
        original_sha256=original.original_sha256,
    )

    with pytest.raises(RuntimeError, match="escaped rollback directory"):
        control.rollback_pending_mutation(reason="tampered runtime metadata")


def test_symlinked_rollback_backup_is_rejected(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")
    assert control.pending_mutation is not None
    original = control.pending_mutation
    original_backup = Path(str(original.backup_path))
    alternate = original_backup.parent / "alternate.bin"
    alternate.write_bytes(original_backup.read_bytes())
    original_backup.unlink()
    try:
        original_backup.symlink_to(alternate)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="symlink"):
        control.rollback_pending_mutation(reason="tampered rollback alias")

    assert control.pending_mutation is not None


def test_snapshot_redacts_pending_details_by_default(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    control.prepare_mutation("tests/test_checkout.py")

    public = control.snapshot()
    persisted = control.snapshot(include_pending_details=True)

    assert public["pending_mutation"] == "tests/test_checkout.py"
    assert isinstance(persisted["pending_mutation"], dict)
    assert persisted["pending_mutation"]["original_sha256"]
    assert persisted["pending_mutation"]["backup_path"]


def test_commit_and_rollback_without_pending_transaction_are_noops(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    assert control.commit_pending_mutation() is None
    assert control.rollback_pending_mutation(reason="nothing") is None
