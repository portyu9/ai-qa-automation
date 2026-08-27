from __future__ import annotations

import json
from pathlib import Path

from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationStatus
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.mutation_lineage import reconcile_rolled_back_mutation
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation


def test_rollback_lineage_reconciliation_is_idempotent() -> None:
    path = "tests/test_checkout.py"
    state = AgentRunState(
        objective="idempotent rollback",
        workspace="/tmp/sut",
        change_revision=2,
        terminal_status=TerminalStatus.SUCCESS,
        files_modified=[path, path],
    )

    assert (
        reconcile_rolled_back_mutation(
            state,
            relative_path=path,
            change_revision_before=1,
        )
        is True
    )
    first_observations = list(state.observations)
    first_validations = list(state.validation_results)
    assert state.files_modified == [path]
    assert state.terminal_status is TerminalStatus.NOT_VERIFIED
    assert first_validations[-1].status is ValidationStatus.NOT_VERIFIED

    assert (
        reconcile_rolled_back_mutation(
            state,
            relative_path=path,
            change_revision_before=1,
        )
        is True
    )
    assert state.files_modified == [path]
    assert state.observations == first_observations
    assert state.validation_results == first_validations


def test_stale_recovery_requires_canonical_state_before_target_write(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir(parents=True)
    target.write_text("generated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    stat = workspace.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {"device": stat.st_dev, "inode": stat.st_ino},
        "workspace_fingerprint": "fp",
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": "tests/test_generated.py",
            "existed": False,
            "backup_path": None,
            "original_sha256": None,
            "change_revision_before": 0,
        },
    }
    (prior_run / "runtime.json").write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "prior canonical state" in str(result["reason"])
    assert target.read_text(encoding="utf-8") == "generated\n"
    persisted = json.loads((prior_run / "runtime.json").read_text(encoding="utf-8"))
    assert persisted["pending_mutation"] is not None
