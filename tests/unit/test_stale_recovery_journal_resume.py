from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState, ValidationStatus
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _workspace_fingerprint(workspace: Path) -> str:
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    return snapshot.fingerprint


def _setup_pending_recovery(tmp_path: Path) -> dict[str, object]:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    relative_path = "tests/test_checkout.py"
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    original = b"original\n"
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
    target.write_text("candidate\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(original)

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    candidate_fingerprint = _workspace_fingerprint(workspace)
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

    state_path = prior_run / "state.json"
    StateStore(state_path).save(
        AgentRunState(
            run_id="run-old",
            objective="stale recovery journal resumption",
            workspace=str(workspace),
            change_revision=1,
            files_modified=[relative_path],
        )
    )
    previous_lease = {
        "run_id": "run-old",
        "run_root_identity": {
            "device": run_root_stat.st_dev,
            "inode": run_root_stat.st_ino,
        },
    }
    return {
        "artifact_root": artifact_root,
        "workspace": workspace,
        "relative_path": relative_path,
        "target": target,
        "prior_run": prior_run,
        "backup": backup,
        "original": original,
        "journal": journal,
        "candidate_fingerprint": candidate_fingerprint,
        "runtime_path": runtime_path,
        "state_path": state_path,
        "previous_lease": previous_lease,
    }


def test_stale_recovery_resumes_exact_durable_tail_without_duplicate_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup_pending_recovery(tmp_path)
    state_path = setup["state_path"]
    assert isinstance(state_path, Path)
    original_save = StateStore.save

    def fail_prior_state_save(self: StateStore, state: AgentRunState) -> None:
        if self.path == state_path:
            raise OSError("simulated stale recovery state checkpoint failure")
        original_save(self, state)

    monkeypatch.setattr(StateStore, "save", fail_prior_state_save)
    first = recover_stale_mutation(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=setup["workspace"],  # type: ignore[arg-type]
        previous_lease=setup["previous_lease"],  # type: ignore[arg-type]
        current_workspace_fingerprint=setup["candidate_fingerprint"],  # type: ignore[arg-type]
        recovering_run_id="run-recovery-1",
    )
    assert first["status"] == "BLOCKED"
    assert "canonical validation lineage could not be durably reconciled" in str(first["reason"])

    target = setup["target"]
    backup = setup["backup"]
    original = setup["original"]
    journal = setup["journal"]
    workspace = setup["workspace"]
    runtime_path = setup["runtime_path"]
    assert isinstance(target, Path)
    assert isinstance(backup, Path)
    assert isinstance(original, bytes)
    assert isinstance(journal, RunJournal)
    assert isinstance(workspace, Path)
    assert isinstance(runtime_path, Path)
    assert target.read_bytes() == original
    assert backup.is_file()
    assert journal.verify()["events"] == 2

    tail_status = journal.verify(include_last_record=True)
    tail = tail_status["last_record"]
    assert isinstance(tail, dict)
    assert tail["event"] == "stale_mutation_recovered"
    assert tail["payload"]["recovering_run_id"] == "run-recovery-1"
    recovered_fingerprint = _workspace_fingerprint(workspace)
    assert tail["payload"]["recovered_workspace_fingerprint"] == recovered_fingerprint

    monkeypatch.undo()
    resumed = recover_stale_mutation(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=workspace,
        previous_lease=setup["previous_lease"],  # type: ignore[arg-type]
        current_workspace_fingerprint=recovered_fingerprint,
        recovering_run_id="run-recovery-2",
    )

    assert resumed == {
        "status": "RECOVERED",
        "previous_run_id": "run-old",
        "path": setup["relative_path"],
        "resumed_recovery_event": True,
    }
    assert target.read_bytes() == original
    assert not backup.exists()
    assert journal.verify()["events"] == 2

    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert persisted_runtime["pending_mutation"] is None
    assert persisted_runtime["recovered_by_run_id"] == "run-recovery-1"
    assert persisted_runtime["journal_event_count"] == 2
    assert persisted_runtime["journal_head_hash"] == journal.verify()["head_hash"]

    persisted_state = StateStore(state_path).load()
    assert setup["relative_path"] not in persisted_state.files_modified
    rolled_back = [
        item
        for item in persisted_state.validation_results
        if item.name == "mutation_transaction"
        and item.details.get("scope") == "rolled_back_mutation"
    ]
    assert len(rolled_back) == 1
    assert rolled_back[0].status is ValidationStatus.NOT_VERIFIED


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    [
        ("path", "tests/test_other.py"),
        ("previous_run_id", "run-other"),
        ("change_revision_before", 9),
    ],
)
def test_stale_recovery_rejects_wrong_subject_tail_before_target_write(
    tmp_path: Path,
    field: str,
    wrong_value: object,
) -> None:
    setup = _setup_pending_recovery(tmp_path)
    journal = setup["journal"]
    target = setup["target"]
    backup = setup["backup"]
    runtime_path = setup["runtime_path"]
    assert isinstance(journal, RunJournal)
    assert isinstance(target, Path)
    assert isinstance(backup, Path)
    assert isinstance(runtime_path, Path)
    candidate_bytes = target.read_bytes()
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))

    payload: dict[str, object] = {
        "recovering_run_id": "run-recovery-1",
        "previous_run_id": "run-old",
        "path": setup["relative_path"],
        "change_revision_before": 0,
        "runtime_event_count": runtime["journal_event_count"],
        "runtime_head_hash": runtime["journal_head_hash"],
        "recovered_workspace_fingerprint": setup["candidate_fingerprint"],
    }
    payload[field] = wrong_value
    journal.append("stale_mutation_recovered", **payload)

    result = recover_stale_mutation(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=setup["workspace"],  # type: ignore[arg-type]
        previous_lease=setup["previous_lease"],  # type: ignore[arg-type]
        current_workspace_fingerprint=setup["candidate_fingerprint"],  # type: ignore[arg-type]
        recovering_run_id="run-recovery-2",
    )

    assert result["status"] == "BLOCKED"
    assert "prior runtime journal authority is invalid" in str(result["reason"])
    assert target.read_bytes() == candidate_bytes
    assert backup.is_file()
    assert journal.verify()["events"] == 2
    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)


def test_stale_recovery_rejects_workspace_drift_after_durable_recovery_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    setup = _setup_pending_recovery(tmp_path)
    state_path = setup["state_path"]
    workspace = setup["workspace"]
    target = setup["target"]
    backup = setup["backup"]
    journal = setup["journal"]
    assert isinstance(state_path, Path)
    assert isinstance(workspace, Path)
    assert isinstance(target, Path)
    assert isinstance(backup, Path)
    assert isinstance(journal, RunJournal)
    original_save = StateStore.save

    def fail_prior_state_save(self: StateStore, state: AgentRunState) -> None:
        if self.path == state_path:
            raise OSError("simulated stale recovery state checkpoint failure")
        original_save(self, state)

    monkeypatch.setattr(StateStore, "save", fail_prior_state_save)
    first = recover_stale_mutation(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=workspace,
        previous_lease=setup["previous_lease"],  # type: ignore[arg-type]
        current_workspace_fingerprint=setup["candidate_fingerprint"],  # type: ignore[arg-type]
        recovering_run_id="run-recovery-1",
    )
    assert first["status"] == "BLOCKED"
    assert journal.verify()["events"] == 2
    assert backup.is_file()

    monkeypatch.undo()
    recovered_fingerprint = _workspace_fingerprint(workspace)
    unrelated = workspace / "unrelated.txt"
    unrelated.write_text("newer work\n", encoding="utf-8")
    drifted_fingerprint = _workspace_fingerprint(workspace)
    assert drifted_fingerprint != recovered_fingerprint
    restored_bytes = target.read_bytes()

    result = recover_stale_mutation(
        artifact_root=setup["artifact_root"],  # type: ignore[arg-type]
        workspace=workspace,
        previous_lease=setup["previous_lease"],  # type: ignore[arg-type]
        current_workspace_fingerprint=drifted_fingerprint,
        recovering_run_id="run-recovery-2",
    )

    assert result["status"] == "BLOCKED"
    assert "workspace changed after a durable stale recovery event" in str(result["reason"])
    assert target.read_bytes() == restored_bytes
    assert unrelated.read_text(encoding="utf-8") == "newer work\n"
    assert backup.is_file()
    assert journal.verify()["events"] == 2
