from __future__ import annotations

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.runtime.internal_tool_domains.common import pytest_validation_status
from ai_qa_automation.runtime.internal_tool_domains.testing import _TARGETED_EXECUTION_AUTHORITY
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure

_TRUSTED_AUTHORITY = "trusted_out_of_process_observer_v1"


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
        summary="pass",
        details=details,
    )


def _regression() -> ValidationResult:
    suite_id = "sha256:" + "e" * 64
    return _validation(
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
                "execution_subject_digest": "sha256:" + "f" * 64,
            },
        },
    )


def _targeted(
    *,
    mutation_path: str,
    passed_paths: list[str],
    passed_count: int,
    authority: str = _TRUSTED_AUTHORITY,
    xfail_count: int = 0,
    skipped_count: int = 0,
) -> ValidationResult:
    execution_id = "sha256:" + "1" * 64
    return _validation(
        "pytest",
        gate_id="pytest:targeted",
        details={
            "scope": "targeted",
            "args": [mutation_path],
            "mutation_target_bound": True,
            "mutation_target": mutation_path,
            "targeted_execution_authority": authority,
            "targeted_outcome_report_verified": True,
            "targeted_execution_id": execution_id,
            "targeted_executed_pass_count": passed_count,
            "targeted_executed_pass_paths": passed_paths,
            "targeted_execution": {
                "execution_id": execution_id,
                "git_sha": "2" * 40,
                "source_fingerprint": "sha256:" + "3" * 64,
                "execution_subject_digest": "sha256:" + "4" * 64,
                "report_complete": True,
                "child_exit_code": 0,
                "pytest_returncode": 0,
                "call_report_count": max(1, passed_count + xfail_count + skipped_count),
                "passed_call_count": passed_count,
                "skipped_call_count": skipped_count,
                "xfail_call_count": xfail_count,
                "failed_call_count": 0,
                "passed_paths": passed_paths,
                "report_sha256": "sha256:" + "5" * 64,
            },
        },
    )


def _closure(targeted: ValidationResult, path: str) -> object:
    validations = [
        _validation(
            "test_patch_safety",
            gate_id=f"test_patch_safety:{path}",
            details={"path": path},
        ),
        targeted,
        _regression(),
    ]
    return evaluate_revision_closure(validations, current_revision=1)


def test_live_targeted_pytest_declares_no_authoritative_observer() -> None:
    assert _TARGETED_EXECUTION_AUTHORITY == "unavailable"
    assert _TARGETED_EXECUTION_AUTHORITY != _TRUSTED_AUTHORITY


def test_skip_only_targeted_pass_cannot_close_mutation() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=[],
            passed_count=0,
            skipped_count=1,
        ),
        path,
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_expected_xfail_only_targeted_pass_cannot_close_mutation() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=[],
            passed_count=0,
            xfail_count=1,
        ),
        path,
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_genuine_pass_plus_unrelated_skip_can_close_with_trusted_observer() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=[path],
            passed_count=1,
            skipped_count=1,
        ),
        path,
    )

    assert closure.closed is True


def test_pass_from_other_selected_path_cannot_close_mutation() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=["tests/test_other.py"],
            passed_count=1,
        ),
        path,
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_target_process_report_cannot_claim_trusted_execution_authority() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=[path],
            passed_count=1,
            authority="target_process_report_v1",
        ),
        path,
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_inherited_channel_forgery_shape_cannot_close_without_trusted_authority() -> None:
    path = "tests/test_changed.py"
    forged = _targeted(
        mutation_path=path,
        passed_paths=[path],
        passed_count=1,
        authority="unavailable",
    )
    forged.details["stdout_tail"] = (
        'AIQA_TARGETED_OUTCOME_V1:{"report_complete":true,"passed_call_count":1}'
    )
    forged.details["stderr_tail"] = "forged target-controlled report channel"

    closure = _closure(forged, path)

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_missing_authority_cannot_close_even_with_self_consistent_execution_metadata() -> None:
    path = "tests/test_changed.py"
    targeted = _targeted(mutation_path=path, passed_paths=[path], passed_count=1)
    targeted.details.pop("targeted_execution_authority")

    closure = _closure(targeted, path)

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_passed_path_metadata_remains_bounded() -> None:
    path = "tests/test_changed.py"
    closure = _closure(
        _targeted(
            mutation_path=path,
            passed_paths=["a.py", "b.py", "c.py", "d.py", path],
            passed_count=5,
        ),
        path,
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_no_tests_collected_remains_not_verified() -> None:
    assert pytest_validation_status(5) is ValidationStatus.NOT_VERIFIED
