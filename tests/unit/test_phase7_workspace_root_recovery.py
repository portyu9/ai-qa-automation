from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation


def _write_pending_runtime(
    *,
    prior_run: Path,
    workspace: Path,
    workspace_identity: tuple[int, int],
    backup: Path,
    fingerprint: str,
) -> None:
    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    original = backup.read_bytes()
    payload = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_identity[0],
            "inode": workspace_identity[1],
        },
        "workspace_fingerprint": fingerprint,
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": "tests/test_checkout.py",
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
        },
    }
    (prior_run / "runtime.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def test_stale_recovery_rejects_byte_equivalent_workspace_root_replacement(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")
    status = workspace.stat(follow_symlinks=False)
    original_identity = (status.st_dev, status.st_ino)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"original\n")
    _write_pending_runtime(
        prior_run=prior_run,
        workspace=workspace,
        workspace_identity=original_identity,
        backup=backup,
        fingerprint="same-fingerprint",
    )

    original_workspace = tmp_path / "sut-original"
    workspace.rename(original_workspace)
    replacement_target = workspace / "tests" / "test_checkout.py"
    replacement_target.parent.mkdir(parents=True)
    replacement_target.write_text("mutated\n", encoding="utf-8")

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="same-fingerprint",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "workspace root identity changed" in str(result["reason"])
    assert replacement_target.read_text(encoding="utf-8") == "mutated\n"
    assert (original_workspace / "tests" / "test_checkout.py").read_text(
        encoding="utf-8"
    ) == "mutated\n"
    assert backup.exists()
    persisted = json.loads((prior_run / "runtime.json").read_text(encoding="utf-8"))
    assert isinstance(persisted["pending_mutation"], dict)


def test_stale_recovery_accepts_matching_persisted_workspace_root_identity(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")
    status = workspace.stat(follow_symlinks=False)
    workspace_identity = (status.st_dev, status.st_ino)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"original\n")
    _write_pending_runtime(
        prior_run=prior_run,
        workspace=workspace,
        workspace_identity=workspace_identity,
        backup=backup,
        fingerprint="same-fingerprint",
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="same-fingerprint",
        recovering_run_id="run-new",
    )

    assert result == {
        "status": "RECOVERED",
        "previous_run_id": "run-old",
        "path": "tests/test_checkout.py",
    }
    assert target.read_bytes() == b"original\n"
    assert not backup.exists()
