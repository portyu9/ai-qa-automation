from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation


def write_runtime(
    path: Path,
    payload: dict[str, object],
    *,
    bind_journal: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = dict(payload)
    pending = rendered.get("pending_mutation")
    if bind_journal and isinstance(pending, dict) and pending:
        journal = RunJournal(path.parent / "journal.jsonl")
        if journal.event_count == 0:
            journal.append("mutation_prepared")
        rendered["journal_event_count"] = journal.event_count
        rendered["journal_head_hash"] = journal.head_hash
    path.write_text(json.dumps(rendered, indent=2, sort_keys=True), encoding="utf-8")


def stale_runtime_payload(
    workspace: Path,
    *,
    relative_path: str,
    existed: bool,
    backup_path: str | None = None,
    original_sha256: str | None = None,
    fingerprint: str = "fp",
) -> dict[str, object]:
    return {
        "workspace": str(workspace.resolve()),
        "workspace_fingerprint": fingerprint,
        "journal_event_count": 0,
        "journal_head_hash": None,
        "pending_mutation": {
            "relative_path": relative_path,
            "existed": existed,
            "backup_path": backup_path,
            "original_sha256": original_sha256,
        },
    }


def recover(artifact_root: Path, workspace: Path, *, fingerprint: str = "fp") -> dict[str, object]:
    return recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint=fingerprint,
        recovering_run_id="run-new",
    )


def test_stale_existing_file_mutation_is_restored_when_fingerprint_matches(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
            fingerprint="fp-after-mutation",
        ),
    )

    result = recover(artifact_root, workspace, fingerprint="fp-after-mutation")

    assert result == {
        "status": "RECOVERED",
        "previous_run_id": "run-old",
        "path": "tests/test_checkout.py",
    }
    assert target.read_bytes() == original
    assert not backup.exists()
    metadata = json.loads((prior_run / "runtime.json").read_text(encoding="utf-8"))
    assert metadata["pending_mutation"] is None
    assert metadata["recovered_by_run_id"] == "run-new"
    assert metadata["recovered_at"]
    journal = RunJournal(prior_run / "journal.jsonl")
    assert metadata["journal_event_count"] == journal.event_count
    assert metadata["journal_head_hash"] == journal.head_hash


def test_operator_edit_after_crash_blocks_automatic_rollback(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("human edit\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
            fingerprint="old-fingerprint",
        ),
    )

    result = recover(artifact_root, workspace, fingerprint="new-human-fingerprint")

    assert result["status"] == "BLOCKED"
    assert "overwriting newer work" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "human edit\n"
    assert backup.exists()


def test_stale_unverified_new_file_is_removed(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "RECOVERED"
    assert not target.exists()


def test_hash_valid_journal_mismatch_blocks_before_stale_rollback(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
    )
    RunJournal(prior_run / "journal.jsonl").append("unexpected_valid_event")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "runtime journal authority does not match persisted journal" in str(result["reason"])
    assert target.exists()


def test_stale_recovery_rejects_symlinked_target_alias(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    actual = workspace / "actual-tests"
    actual.mkdir()
    target = actual / "test_checkout.py"
    target.write_text("mutated\n", encoding="utf-8")
    alias = workspace / "tests"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "symlink" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_stale_recovery_rejects_symlinked_rollback_backup(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    rollback = prior_run / "rollback"
    rollback.mkdir(parents=True)
    original = b"original\n"
    actual_backup = rollback / "actual.bin"
    actual_backup.write_bytes(original)
    alias = rollback / "checkout.bin"
    try:
        alias.symlink_to(actual_backup)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(alias.absolute()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "symlink" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert actual_backup.exists()


def test_stale_recovery_rejects_symlinked_rollback_directory(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    outside_rollback = tmp_path / "outside-rollback"
    outside_rollback.mkdir()
    original = b"original\n"
    backup = outside_rollback / "checkout.bin"
    backup.write_bytes(original)
    rollback_alias = prior_run / "rollback"
    try:
        rollback_alias.symlink_to(outside_rollback, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(original).hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "rollback directory" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_stale_recovery_rejects_symlinked_journal_before_mutation(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated but unverified\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_generated.py",
            existed=False,
        ),
        bind_journal=False,
    )
    outside_journal = tmp_path / "outside-journal.jsonl"
    outside_journal.write_text("do not touch\n", encoding="utf-8")
    journal_alias = prior_run / "journal.jsonl"
    try:
        journal_alias.symlink_to(outside_journal)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "run journal" in str(result["reason"])
    assert target.exists()
    assert outside_journal.read_text(encoding="utf-8") == "do not touch\n"


def test_previous_run_id_traversal_is_blocked(tmp_path: Path) -> None:
    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=tmp_path / "sut",
        previous_lease={"run_id": "../escape"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )
    assert result["status"] == "BLOCKED"
    assert "escapes trusted root" in str(result["reason"])


def test_oversized_runtime_metadata_is_blocked_before_json_ingestion(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    runtime = artifact_root / "run-old" / "runtime.json"
    runtime.parent.mkdir(parents=True)
    runtime.write_bytes(b"{" + (b" " * 2_000_001) + b"}")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "ingestion limit" in str(result["reason"])


def test_non_object_runtime_metadata_is_blocked(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    runtime = artifact_root / "run-old" / "runtime.json"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("[]", encoding="utf-8")

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "root must be an object" in str(result["reason"])


def test_invalid_pending_metadata_is_blocked_not_treated_as_noop(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    write_runtime(
        artifact_root / "run-old" / "runtime.json",
        {
            "workspace": str(workspace.resolve()),
            "workspace_fingerprint": "fp",
            "pending_mutation": "tests/test_x.py",
        },
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "pending mutation metadata is invalid" in str(result["reason"])


def test_oversized_rollback_backup_is_blocked_before_read(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")
    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"x" * 2_000_001)
    write_runtime(
        prior_run / "runtime.json",
        stale_runtime_payload(
            workspace,
            relative_path="tests/test_checkout.py",
            existed=True,
            backup_path=str(backup.resolve()),
            original_sha256=hashlib.sha256(b"original").hexdigest(),
        ),
    )

    result = recover(artifact_root, workspace)

    assert result["status"] == "BLOCKED"
    assert "2 MB" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "mutated\n"
    assert backup.exists()


def test_no_previous_lease_is_noop(tmp_path: Path) -> None:
    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=tmp_path / "sut",
        previous_lease=None,
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result == {"status": "NONE"}
