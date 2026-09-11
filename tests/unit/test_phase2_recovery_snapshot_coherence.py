from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.recovery as recovery_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.state import StateStore


def _persist_revision_zero_run(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")

    run_dir = tmp_path / "run-recovery-snapshot"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    StateStore(run_dir / "state.json").save(
        AgentRunState(
            run_id=run_dir.name,
            objective="prove recovery observes one runtime snapshot",
            workspace=str(workspace.resolve()),
        )
    )
    journal = RunJournal(run_dir / "journal.jsonl")
    journal.append("run_started")
    journal_status = journal.verify()
    workspace_status = workspace.stat(follow_symlinks=False)
    runtime_payload: dict[str, object] = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_status.st_dev,
            "inode": workspace_status.st_ino,
        },
        "journal_event_count": journal_status["events"],
        "journal_head_hash": journal_status["head_hash"],
        "pending_mutation": None,
    }
    runtime_path = run_dir / "runtime.json"
    runtime_path.write_text(json.dumps(runtime_payload, sort_keys=True), encoding="utf-8")
    return run_dir, runtime_path, runtime_payload


def _pending_runtime_payload(runtime_payload: dict[str, object]) -> dict[str, object]:
    changed = dict(runtime_payload)
    changed["pending_mutation"] = {
        "relative_path": "tests/test_checkout.py",
        "existed": False,
        "backup_path": None,
        "original_sha256": None,
        "change_revision_before": 0,
        "candidate_required": True,
        "pre_mutation_workspace_fingerprint": "sha256:" + "1" * 64,
        "pre_mutation_context_fingerprint": "sha256:" + "2" * 64,
        "candidate_sha256": None,
        "candidate_workspace_fingerprint": None,
    }
    return changed


def test_recovery_rejects_runtime_change_during_final_journal_revalidation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, runtime_path, runtime_payload = _persist_revision_zero_run(tmp_path)
    real_read_journal_snapshot = recovery_module._read_journal_snapshot
    journal_reads = 0

    def mutate_runtime_on_final_journal_read(
        observed_run_dir: Path,
        journal_path: Path,
        *,
        run_root_identity: tuple[int, int] | None,
    ) -> bytes:
        nonlocal journal_reads
        journal_reads += 1
        if journal_reads == 2:
            runtime_path.write_text(
                json.dumps(_pending_runtime_payload(runtime_payload), sort_keys=True),
                encoding="utf-8",
            )
        return real_read_journal_snapshot(
            observed_run_dir,
            journal_path,
            run_root_identity=run_root_identity,
        )

    monkeypatch.setattr(
        recovery_module,
        "_read_journal_snapshot",
        mutate_runtime_on_final_journal_read,
    )

    result = inspect_recovery(run_dir)

    assert journal_reads == 2
    assert json.loads(runtime_path.read_text(encoding="utf-8"))["pending_mutation"] is not None
    assert result == {
        "recoverable": False,
        "reason": "runtime.json changed during recovery inspection",
    }
