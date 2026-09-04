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
            details={
                "scope": "targeted",
                "mutation_target_bound": True,
                "mutation_target": path,
            },
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
