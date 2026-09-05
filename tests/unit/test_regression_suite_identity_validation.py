from __future__ import annotations

import pytest

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure


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
    execution_id = "sha256:" + "c" * 64
    passed_paths = [path]
    return {
        "scope": "targeted",
        "mutation_target_bound": True,
        "mutation_target": path,
        "targeted_execution_authority": "trusted_out_of_process_observer_v1",
        "targeted_outcome_report_verified": True,
        "targeted_execution_id": execution_id,
        "targeted_executed_pass_count": 1,
        "targeted_executed_pass_paths": passed_paths,
        "targeted_execution": {
            "execution_id": execution_id,
            "git_sha": "d" * 40,
            "source_fingerprint": "sha256:" + "e" * 64,
            "execution_subject_digest": "sha256:" + "f" * 64,
            "report_complete": True,
            "child_exit_code": 0,
            "pytest_returncode": 0,
            "call_report_count": 1,
            "passed_call_count": 1,
            "skipped_call_count": 0,
            "xfail_call_count": 0,
            "failed_call_count": 0,
            "passed_paths": passed_paths,
            "report_sha256": "sha256:" + "1" * 64,
        },
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


def test_exact_sha256_suite_and_subject_identities_close_revision() -> None:
    closure = evaluate_revision_closure(
        _checks(
            suite_id="sha256:" + "a" * 64,
            subject_digest="sha256:" + "b" * 64,
        ),
        current_revision=1,
    )

    assert closure.closed is True


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
    )

    assert closure.closed is False
    assert closure.code == "unbound_regression_suite"
