from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import AgentRunState, ValidationResult, ValidationStatus
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.regression_execution_observer import (
    TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
    build_regression_execution_observation,
)
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.state import StateStore

_RUN_ID = "run-phase2-recovery-lineage"
_MUTATION_PATH = "tests/test_checkout.py"
_TARGETED_BACKEND = "controller-observer-test-double"
_REGRESSION_BACKEND = "controller-regression-observer-test-double"
_TARGETED_IDENTITY = "sha256:" + "1" * 64
_REGRESSION_IDENTITY = "sha256:" + "6" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64
_SUITE_ID = "sha256:" + "a" * 64
_NODEIDS_SHA256 = "b" * 64


def _trusted_validations(path: str = _MUTATION_PATH) -> list[ValidationResult]:
    targeted = build_targeted_execution_observation(
        run_id=_RUN_ID,
        change_revision=1,
        mutation_path=path,
        pytest_args=(path,),
        observer_backend=_TARGETED_BACKEND,
        observer_identity=_TARGETED_IDENTITY,
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
    suite = {
        "suite_id": _SUITE_ID,
        "git_sha": _GIT_SHA,
        "source_fingerprint": _SOURCE_FINGERPRINT,
        "execution_subject_digest": _SUBJECT_DIGEST,
        "pytest_version": "9.1.1",
        "node_count": 2,
        "nodeids_sha256": _NODEIDS_SHA256,
        "config_path": "pyproject.toml",
        "config_sha256": "c" * 64,
        "config_options": {},
        "conftest_count": 0,
        "conftest_sha256": "d" * 64,
        "manifest_artifact": "pytest/regression-manifest.json",
        "pre_post_collection_match": True,
        "execution_nodes_match": True,
        "execution_root": ".",
        "testpaths_bypassed_by_explicit_root": True,
    }
    regression = build_regression_execution_observation(
        run_id=_RUN_ID,
        change_revision=1,
        pytest_args=(),
        observer_backend=_REGRESSION_BACKEND,
        observer_identity=_REGRESSION_IDENTITY,
        git_sha=_GIT_SHA,
        source_fingerprint=_SOURCE_FINGERPRINT,
        execution_subject_digest=_SUBJECT_DIGEST,
        regression_suite_id=_SUITE_ID,
        node_count=2,
        nodeids_sha256=f"sha256:{_NODEIDS_SHA256}",
        collection_complete=True,
        execution_complete=True,
        report_complete=True,
        child_exit_code=0,
        pytest_returncode=0,
        observed_item_count=2,
        passed_item_count=1,
        skipped_item_count=1,
        xfail_item_count=0,
        xpass_item_count=0,
        failed_item_count=0,
        observed_nodeids_sha256=f"sha256:{_NODEIDS_SHA256}",
        report_sha256="sha256:" + "e" * 64,
    )
    return [
        ValidationResult(
            name="test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            revision=1,
            status=ValidationStatus.PASS,
            summary="safe mutation subject",
            details={"path": path, "scope": "static_patch_safety"},
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:targeted",
            revision=1,
            status=ValidationStatus.PASS,
            summary="trusted targeted pass",
            details={
                "scope": "targeted",
                "args": [path],
                "mutation_target": path,
                "mutation_target_bound": True,
                "targeted_execution_authority": TRUSTED_TARGETED_EXECUTION_AUTHORITY,
                "targeted_outcome_report_verified": True,
                "targeted_observer_backend": _TARGETED_BACKEND,
                "targeted_observer_identity": _TARGETED_IDENTITY,
                "targeted_execution_subject": {
                    "git_sha": _GIT_SHA,
                    "source_fingerprint": _SOURCE_FINGERPRINT,
                    "digest": _SUBJECT_DIGEST,
                    "file_count": 1,
                    "total_bytes": 1,
                    "ignored_inputs_excluded": True,
                    "git_metadata_excluded": True,
                },
                "targeted_execution_id": targeted.execution_id,
                "targeted_executed_pass_count": 1,
                "targeted_executed_pass_paths": [path],
                "targeted_execution": targeted.model_dump(mode="json"),
            },
        ),
        ValidationResult(
            name="pytest",
            gate_id="pytest:regression",
            revision=1,
            status=ValidationStatus.PASS,
            summary="trusted regression pass",
            details={
                "scope": "regression",
                "args": [],
                "regression_suite_verified": False,
                "regression_suite_id": _SUITE_ID,
                "regression_suite": suite,
                "regression_execution_authority": TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
                "regression_outcome_report_verified": True,
                "regression_observer_backend": _REGRESSION_BACKEND,
                "regression_observer_identity": _REGRESSION_IDENTITY,
                "regression_execution_id": regression.execution_id,
                "regression_execution": regression.model_dump(mode="json"),
            },
        ),
    ]


def _persist_closed_run(
    tmp_path: Path,
    *,
    files_modified: list[str],
    change_revision: int = 1,
) -> Path:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root recovery authority is unavailable")
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / _RUN_ID
    state = AgentRunState(
        run_id=_RUN_ID,
        objective="prove persisted recovery mutation lineage",
        workspace=str(workspace),
        change_revision=change_revision,
        files_modified=files_modified,
        validation_results=_trusted_validations() if change_revision == 1 else [],
    )
    StateStore(run_dir / "state.json").save(state)
    journal = RunJournal(run_dir / "journal.jsonl")
    journal.append("validation_closed" if change_revision > 0 else "run_started")
    journal_status = journal.verify()
    workspace_status = workspace.stat(follow_symlinks=False)
    (run_dir / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(workspace.resolve()),
                "workspace_root_identity": {
                    "device": workspace_status.st_dev,
                    "inode": workspace_status.st_ino,
                },
                "journal_event_count": journal_status["events"],
                "journal_head_hash": journal_status["head_hash"],
                "pending_mutation": None,
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def test_recovery_accepts_closed_revision_when_mutation_path_is_canonical(tmp_path: Path) -> None:
    result = inspect_recovery(
        _persist_closed_run(tmp_path, files_modified=[_MUTATION_PATH])
    )

    assert result["recoverable"] is True
    assert result["revision_closed"] is True
    assert result["revision_closure"] == {
        "closed": True,
        "code": "closed",
        "reason": "Current changed revision is deterministically closed.",
        "mutation_path": _MUTATION_PATH,
    }
    assert result["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"


@pytest.mark.parametrize(
    "files_modified",
    [
        [],
        ["tests/test_other.py"],
    ],
)
def test_recovery_denies_closed_validation_with_incoherent_modified_file_lineage(
    tmp_path: Path,
    files_modified: list[str],
) -> None:
    result = inspect_recovery(
        _persist_closed_run(tmp_path, files_modified=files_modified)
    )

    assert result["recoverable"] is True
    assert result["revision_closed"] is False
    assert result["revision_closure"] == {
        "closed": False,
        "code": "canonical_mutation_lineage_mismatch",
        "reason": (
            "Persisted validation closure mutation subject is absent from canonical "
            "modified-file lineage."
        ),
        "mutation_path": _MUTATION_PATH,
    }
    assert result["resume_policy"] == "manual-review-required-before-new-session"


def test_recovery_denies_revision_zero_with_modified_file_lineage(tmp_path: Path) -> None:
    result = inspect_recovery(
        _persist_closed_run(
            tmp_path,
            files_modified=[_MUTATION_PATH],
            change_revision=0,
        )
    )

    assert result["recoverable"] is True
    assert result["change_revision"] == 0
    assert result["revision_closed"] is False
    assert result["revision_closure"] == {
        "closed": False,
        "code": "canonical_mutation_lineage_mismatch",
        "reason": (
            "Persisted revision zero contains modified-file lineage without a canonical changed "
            "revision."
        ),
        "mutation_path": None,
    }
    assert result["resume_policy"] == "manual-review-required-before-new-session"


def test_recovery_accepts_current_closure_path_among_historical_modified_paths(
    tmp_path: Path,
) -> None:
    result = inspect_recovery(
        _persist_closed_run(
            tmp_path,
            files_modified=["tests/test_prior.py", _MUTATION_PATH],
        )
    )

    assert result["revision_closed"] is True
    assert result["resume_policy"] == "safe-to-start-a-new-agent-session-from-persisted-evidence"
