from __future__ import annotations

import pytest

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure

_RUN_ID = "run-regression-suite-identity"
_OBSERVER_BACKEND = "controller-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64


def _validation(
    name: str,
    *,
    gate_id: str,
    details: dict[str, object],
) -> ValidationResult:
    return ValidationResult(
        name=name,
        gate_id=gate_id,
        revision=1,
        status=ValidationStatus.PASS,
        summary="fixture pass",
        details=details,
    )


def _targeted_details(path: str) -> dict[str, object]:
    passed_paths = [path]
    observer = build_targeted_execution_observation(
        run_id=_RUN_ID,
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
        passed_paths=tuple(passed_paths),
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
        "targeted_executed_pass_paths": passed_paths,
        "targeted_execution": observer.model_dump(mode="json"),
    }


def _checks(*, suite_id: str, subject_digest: str) -> list[ValidationResult]:
    path = "tests/test_checkout.py"
    return [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        _validation(
            "pytest",
            gate_id="pytest:targeted",
            details=_targeted_details(path),
        ),
        _validation(
            "pytest",
            gate_id="pytest:regression",
            details={
                "scope": "regression",
                "regression_suite_verified": True,
                "regression_suite_id": suite_id,
                "regression_suite": {
                    "suite_id": suite_id,
                    "pre_post_collection_match": True,
                    "execution_nodes_match": True,
                    "node_count": 1,
                    "execution_subject_digest": subject_digest,
                },
            },
        ),
    ]


def test_legacy_plausible_regression_suite_cannot_close_revision() -> None:
    closure = evaluate_revision_closure(
        _checks(
            suite_id="sha256:" + "a" * 64,
            subject_digest="sha256:" + "b" * 64,
        ),
        current_revision=1,
        expected_run_id=_RUN_ID,
    )

    assert closure.closed is False
    assert closure.code == "unbound_regression_suite"
    assert "independently trusted" in closure.reason


@pytest.mark.parametrize(
    ("suite_id", "subject_digest"),
    [
        ("sha256:x", "sha256:" + "b" * 64),
        ("sha256:" + "g" * 64, "sha256:" + "b" * 64),
        ("sha256:" + "a" * 64, "sha256:x"),
        ("sha256:" + "a" * 64, "sha256:" + "g" * 64),
    ],
)
def test_malformed_regression_identities_fail_closed(
    suite_id: str,
    subject_digest: str,
) -> None:
    closure = evaluate_revision_closure(
        _checks(suite_id=suite_id, subject_digest=subject_digest),
        current_revision=1,
        expected_run_id=_RUN_ID,
    )

    assert closure.closed is False
    assert closure.code == "unbound_regression_suite"
