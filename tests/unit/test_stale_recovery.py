from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation


def write_runtime(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


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
        {
            "workspace": str(workspace.resolve()),
            "workspace_fingerprint": "fp-after-mutation",
            "journal_event_count": 0,
            "pending_mutation": {
                "relative_path": "tests/test_checkout.py",
                "existed": True,
                "backup_path": str(backup.resolve()),
                "original_sha256": hashlib.sha256(original).hexdigest(),
            },
        },
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp-after-mutation",
        recovering_run_id="run-new",
    )

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
        {
            "workspace": str(workspace.resolve()),
            "workspace_fingerprint": "old-fingerprint",
            "pending_mutation": {
                "relative_path": "tests/test_checkout.py",
                "existed": True,
                "backup_path": str(backup.resolve()),
                "original_sha256": hashlib.sha256(original).hexdigest(),
            },
        },
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="new-human-fingerprint",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "overwriting newer work" in result["reason"]
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
        {
            "workspace": str(workspace.resolve()),
            "workspace_fingerprint": "fp",
            "pending_mutation": {
                "relative_path": "tests/test_generated.py",
                "existed": False,
                "backup_path": None,
                "original_sha256": None,
            },
        },
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "RECOVERED"
    assert not target.exists()


def test_no_previous_lease_is_noop(tmp_path: Path) -> None:
    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=tmp_path / "sut",
        previous_lease=None,
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result == {"status": "NONE"}
