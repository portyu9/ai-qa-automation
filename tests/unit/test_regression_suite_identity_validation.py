from __future__ import annotations

import pytest

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.runtime.regression_execution_observer import (
    TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
    build_regression_execution_observation,
)
from ai_qa_automation.runtime.targeted_execution_observer import (
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    build_targeted_execution_observation,
)
from ai_qa_automation.runtime.validation_truth import evaluate_revision_closure

_RUN_ID = "run-regression-suite-identity"
_OBSERVER_BACKEND = "controller-observer-test-double"
_REGRESSION_OBSERVER_BACKEND = "controller-regression-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_REGRESSION_OBSERVER_IDENTITY = "sha256:" + "6" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64
_SUITE_ID = "sha256:" + "a" * 64
_NODEIDS_SHA256 = "b" * 64


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


def _suite_details(
    *, suite_id: str = _SUITE_ID, nodeids_sha256: str = _NODEIDS_SHA256
) -> dict[str, object]:
    return {
        "suite_id": suite_id,
        "git_sha": _GIT_SHA,
        "source_fingerprint": _SOURCE_FINGERPRINT,
        "execution_subject_digest": _SUBJECT_DIGEST,
        "pytest_version": "9.1.1",
        "node_count": 2,
        "nodeids_sha256": nodeids_sha256,
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


def _strict_regression_details(
    *,
    suite_id: str = _SUITE_ID,
    nodeids_sha256: str = _NODEIDS_SHA256,
) -> dict[str, object]:
    suite = _suite_details(suite_id=suite_id, nodeids_sha256=nodeids_sha256)
    observer = build_regression_execution_observation(
        run_id=_RUN_ID,
        change_revision=1,
        pytest_args=(),
        observer_backend=_REGRESSION_OBSERVER_BACKEND,
        observer_identity=_REGRESSION_OBSERVER_IDENTITY,
        git_sha=_GIT_SHA,
        source_fingerprint=_SOURCE_FINGERPRINT,
        execution_subject_digest=_SUBJECT_DIGEST,
        regression_suite_id=suite_id,
        node_count=2,
        nodeids_sha256=f"sha256:{nodeids_sha256}",
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
        observed_nodeids_sha256=f"sha256:{nodeids_sha256}",
        report_sha256="sha256:" + "e" * 64,
    )
    return {
        "scope": "regression",
        "args": [],
        "regression_suite_verified": False,
        "regression_suite_id": suite_id,
        "regression_suite": suite,
        "regression_execution_authority": TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
        "regression_outcome_report_verified": True,
        "regression_observer_backend": _REGRESSION_OBSERVER_BACKEND,
        "regression_observer_identity": _REGRESSION_OBSERVER_IDENTITY,
        "regression_execution_id": observer.execution_id,
        "regression_execution": observer.model_dump(mode="json"),
    }


def _legacy_regression_details(*, suite_id: str, subject_digest: str) -> dict[str, object]:
    return {
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
    }


def _checks(regression_details: dict[str, object]) -> list[ValidationResult]:
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
            details=regression_details,
        ),
    ]


def test_strict_external_regression_observation_closes_consumer_contract() -> None:
    closure = evaluate_revision_closure(
        _checks(_strict_regression_details()),
        current_revision=1,
        expected_run_id=_RUN_ID,
    )

    assert closure.closed is True
    assert closure.code == "closed"


def test_legacy_plausible_regression_suite_cannot_close_revision() -> None:
    closure = evaluate_revision_closure(
        _checks(
            _legacy_regression_details(
                suite_id=_SUITE_ID,
                subject_digest="sha256:" + "b" * 64,
            )
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
def test_malformed_legacy_regression_identities_fail_closed(
    suite_id: str,
    subject_digest: str,
) -> None:
    closure = evaluate_revision_closure(
        _checks(
            _legacy_regression_details(
                suite_id=suite_id,
                subject_digest=subject_digest,
            )
        ),
        current_revision=1,
        expected_run_id=_RUN_ID,
    )

    assert closure.closed is False
    assert closure.code == "unbound_regression_suite"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("regression_execution_authority", "target_process_report_v1"),
        ("regression_outcome_report_verified", False),
        ("regression_observer_backend", "other-observer"),
        ("regression_observer_identity", "sha256:" + "f" * 64),
        ("regression_execution_id", "sha256:" + "0" * 64),
    ],
)
def test_regression_top_level_authority_tampering_fails_closed(
    field: str,
    replacement: object,
) -> None:
    details = _strict_regression_details()
    details[field] = replacement

    closure = evaluate_revision_closure(
        _checks(details),
        current_revision=1,
        expected_run_id=_RUN_ID,
    )

    assert closure.closed is False
    assert closure.code == "unbound_regression_suite"


def test_cross_run_regression_observation_replay_fails_closed() -> None:
    closure = evaluate_revision_closure(
        _checks(_strict_regression_details()),
        current_revision=1,
        expected_run_id="run-other",
    )

    assert closure.closed is False
    assert closure.code == "incomplete_pytest_closure"


def test_regression_suite_subject_tampering_fails_closed() -> None:
    for field, replacement in (
        ("git_sha", "9" * 40),
        ("source_fingerprint", "sha256:" + "8" * 64),
        ("execution_subject_digest", "sha256:" + "7" * 64),
        ("node_count", 3),
        ("nodeids_sha256", "6" * 64),
        ("execution_root", "tests"),
        ("testpaths_bypassed_by_explicit_root", False),
        ("pre_post_collection_match", False),
        ("execution_nodes_match", False),
    ):
        details = _strict_regression_details()
        suite = dict(details["regression_suite"])
        suite[field] = replacement
        details["regression_suite"] = suite
        closure = evaluate_revision_closure(
            _checks(details),
            current_revision=1,
            expected_run_id=_RUN_ID,
        )
        assert closure.closed is False
        assert closure.code == "unbound_regression_suite"
