from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector

_LEASE_ID = "lease-old"


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _fingerprint(workspace: Path) -> str:
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    return snapshot.fingerprint


def test_exact_shaped_recovery_tail_cannot_replace_rollback_byte_proof(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    original = b"original\n"
    candidate = b"candidate\n"
    target.write_bytes(original)
    _git(workspace, "init", "-q")
    _git(workspace, "add", "--", relative_path)
    _git(
        workspace,
        "-c",
        "user.name=QA Fixture",
        "-c",
        "user.email=qa-fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture baseline",
    )
    pre_fingerprint = _fingerprint(workspace)
    target.write_bytes(candidate)
    candidate_fingerprint = _fingerprint(workspace)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(original)

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    workspace_stat = workspace.stat(follow_symlinks=False)
    run_root_stat = prior_run.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_stat.st_dev,
            "inode": workspace_stat.st_ino,
        },
        "workspace_fingerprint": candidate_fingerprint,
        "lease_id": _LEASE_ID,
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": relative_path,
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "change_revision_before": 0,
            "candidate_required": True,
            "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
            "candidate_workspace_fingerprint": candidate_fingerprint,
            "pre_mutation_workspace_fingerprint": pre_fingerprint,
        },
    }
    runtime_path = prior_run / "runtime.json"
    runtime_path.write_text(json.dumps(runtime, indent=2, sort_keys=True), encoding="utf-8")
    StateStore(prior_run / "state.json").save(
        AgentRunState(
            run_id="run-old",
            objective="forged stale recovery tail",
            workspace=str(workspace),
            change_revision=1,
            files_modified=[relative_path],
        )
    )

    # The record is structurally perfect and is chained to the exact stale runtime
    # predecessor, but it lies about rollback having occurred. Journal structure is
    # evidence, not authorization to close recovery, and cannot replace candidate proof.
    journal.append(
        "stale_mutation_recovered",
        recovering_run_id="run-forger",
        previous_run_id="run-old",
        path=relative_path,
        change_revision_before=0,
        runtime_event_count=runtime["journal_event_count"],
        runtime_head_hash=runtime["journal_head_hash"],
        recovered_workspace_fingerprint=candidate_fingerprint,
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={
            "run_id": "run-old",
            "lease_id": _LEASE_ID,
            "run_root_identity": {
                "device": run_root_stat.st_dev,
                "inode": run_root_stat.st_ino,
            },
        },
        current_workspace_fingerprint=candidate_fingerprint,
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "lost its exact candidate proof" in str(result["reason"])
    assert target.read_bytes() == candidate
    assert backup.is_file()
    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)
    assert journal.event_count == 2
