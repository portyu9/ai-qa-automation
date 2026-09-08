from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector


def test_exact_shaped_recovery_tail_cannot_replace_rollback_byte_proof(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    candidate = b"candidate\n"
    target.write_bytes(candidate)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    candidate_fingerprint = snapshot.fingerprint
    workspace_stat = workspace.stat(follow_symlinks=False)
    run_root_stat = prior_run.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_stat.st_dev,
            "inode": workspace_stat.st_ino,
        },
        "workspace_fingerprint": candidate_fingerprint,
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": relative_path,
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "change_revision_before": 0,
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
    # predecessor, but it lies about rollback having occurred. The candidate bytes
    # still exist. Journal structure is evidence, not authorization to close recovery.
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
            "run_root_identity": {
                "device": run_root_stat.st_dev,
                "inode": run_root_stat.st_ino,
            },
        },
        current_workspace_fingerprint=candidate_fingerprint,
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "does not match the current rollback target bytes" in str(result["reason"])
    assert target.read_bytes() == candidate
    assert backup.is_file()
    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)
    assert journal.event_count == 2
