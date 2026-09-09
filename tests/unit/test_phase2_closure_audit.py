from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.models import (
    AgentRunState,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector

_OBSERVER_BACKEND = "controller-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64
_STRICT_LEASE_ID = "lease-old"


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


def _verified_regression_details() -> dict[str, object]:
    suite_id = "sha256:" + "a" * 64
    return {
        "scope": "regression",
        "regression_suite_verified": True,
        "regression_suite_id": suite_id,
        "regression_suite": {
            "suite_id": suite_id,
            "pre_post_collection_match": True,
            "execution_nodes_match": True,
            "node_count": 1,
            "execution_subject_digest": "sha256:" + "b" * 64,
        },
    }


def _verified_targeted_details(path: str, *, run_id: str) -> dict[str, object]:
    observer = build_targeted_execution_observation(
        run_id=run_id,
        change_revision=1,
        mutation_path=path,
        pytest_args=(path,),
        observer_backend=_OBSERVER_BACKEND,
        observer_identity=_OBSERVER_IDENTITY,
        git_sha=_GIT_SHA,
        source_fingerprint=_SOURCE_FINGERPRINT,
        execution_subject_digest=_SUBJECT_DIGEST,
        report_complete=True,
        child_exit_code=0,
        pytest_returncode=0,
        call_report_count=1,
        passed_call_count=1,
        skipped_call_count=0,
        xfail_call_count=0,
        failed_call_count=0,
        passed_paths=(path,),
        report_sha256="sha256:" + "5" * 64,
    )
    return {
        "scope": "targeted",
        "args": [path],
        "mutation_target_bound": True,
        "mutation_target": path,
        "targeted_execution_authority": TRUSTED_TARGETED_EXECUTION_AUTHORITY,
        "targeted_outcome_report_verified": True,
        "targeted_observer_backend": _OBSERVER_BACKEND,
        "targeted_observer_identity": _OBSERVER_IDENTITY,
        "targeted_execution_subject": {
            "git_sha": _GIT_SHA,
            "source_fingerprint": _SOURCE_FINGERPRINT,
            "digest": _SUBJECT_DIGEST,
            "file_count": 1,
            "total_bytes": 1,
            "ignored_inputs_excluded": True,
            "git_metadata_excluded": True,
        },
        "targeted_execution_id": observer.execution_id,
        "targeted_executed_pass_count": 1,
        "targeted_executed_pass_paths": [path],
        "targeted_execution": observer.model_dump(mode="json"),
    }


def _legacy_positive_revision_checks(path: str, *, run_id: str) -> list[ValidationResult]:
    return [
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=1,
            status=ValidationStatus.PASS,
            summary="patch safety passed",
            details={"path": path},
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:targeted",
            revision=1,
            status=ValidationStatus.PASS,
            summary="targeted pytest passed",
            details=_verified_targeted_details(path, run_id=run_id),
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:regression",
            revision=1,
            status=ValidationStatus.PASS,
            summary="legacy regression claim",
            details=_verified_regression_details(),
        ),
    ]


def test_stale_recovery_state_checkpoint_failure_keeps_runtime_pending_after_restore(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    pre_fingerprint = _workspace_fingerprint(workspace)
    target.write_bytes(candidate)
    candidate_fingerprint = _workspace_fingerprint(workspace)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(original)

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    root_stat = workspace.stat(follow_symlinks=False)
    run_root_stat = prior_run.stat(follow_symlinks=False)
    runtime = {
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": root_stat.st_dev,
            "inode": root_stat.st_ino,
        },
        "workspace_fingerprint": candidate_fingerprint,
        "lease_id": _STRICT_LEASE_ID,
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
    runtime_path.write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    state_path = prior_run / "state.json"
    prior_state = AgentRunState(
        run_id="run-old",
        objective="state checkpoint failure after stale rollback restore",
        workspace=str(workspace),
        change_revision=1,
        terminal_status=TerminalStatus.SUCCESS,
        files_modified=[relative_path],
        validation_results=_legacy_positive_revision_checks(relative_path, run_id="run-old"),
    )
    StateStore(state_path).save(prior_state)
    current_closure = evaluate_revision_closure(
        prior_state.validation_results,
        current_revision=prior_state.change_revision,
        expected_run_id=prior_state.run_id,
    )
    assert current_closure.closed is False
    assert current_closure.code == "unbound_regression_suite"

    original_save = StateStore.save

    def fail_prior_state_save(self: StateStore, state: AgentRunState) -> None:
        if self.path == state_path:
            raise OSError("simulated stale recovery state checkpoint failure")
        original_save(self, state)

    monkeypatch.setattr(StateStore, "save", fail_prior_state_save)

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={
            "run_id": "run-old",
            "lease_id": _STRICT_LEASE_ID,
            "run_root_identity": {
                "device": run_root_stat.st_dev,
                "inode": run_root_stat.st_ino,
            },
        },
        current_workspace_fingerprint=candidate_fingerprint,
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "canonical validation lineage could not be durably reconciled" in str(result["reason"])
    assert target.read_bytes() == original
    assert backup.is_file()

    persisted_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert isinstance(persisted_runtime["pending_mutation"], dict)

    persisted_state = StateStore(state_path).load()
    assert persisted_state.terminal_status is TerminalStatus.SUCCESS
    assert persisted_state.files_modified == [relative_path]
    persisted_closure = evaluate_revision_closure(
        persisted_state.validation_results,
        current_revision=persisted_state.change_revision,
        expected_run_id=persisted_state.run_id,
    )
    assert persisted_closure.closed is False
    assert persisted_closure.code == "unbound_regression_suite"

    inspection = inspect_recovery(prior_run)
    assert inspection["recoverable"] is False
    assert "runtime journal authority is invalid" in str(inspection["reason"])
