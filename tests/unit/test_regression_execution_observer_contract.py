from __future__ import annotations

import pytest

from ai_qa_automation.runtime.regression_execution_observer import (
    REGRESSION_EXECUTION_SCHEMA,
    TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
    RegressionExecutionObservation,
    build_regression_execution_observation,
    verified_regression_execution_observation,
)

_RUN_ID = "run-regression-observer-contract"
_OBSERVER_BACKEND = "controller-regression-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64
_SUITE_ID = "sha256:" + "5" * 64
_NODEIDS_DIGEST = "sha256:" + "6" * 64


def observation(**overrides: object) -> RegressionExecutionObservation:
    values: dict[str, object] = {
        "schema_version": REGRESSION_EXECUTION_SCHEMA,
        "authority": TRUSTED_REGRESSION_EXECUTION_AUTHORITY,
        "run_id": _RUN_ID,
        "change_revision": 2,
        "pytest_args": ("-q",),
        "observer_backend": _OBSERVER_BACKEND,
        "observer_identity": _OBSERVER_IDENTITY,
        "git_sha": _GIT_SHA,
        "source_fingerprint": _SOURCE_FINGERPRINT,
        "execution_subject_digest": _SUBJECT_DIGEST,
        "regression_suite_id": _SUITE_ID,
        "node_count": 4,
        "nodeids_sha256": _NODEIDS_DIGEST,
        "collection_complete": True,
        "execution_complete": True,
        "report_complete": True,
        "child_exit_code": 0,
        "pytest_returncode": 0,
        "observed_item_count": 4,
        "passed_item_count": 1,
        "skipped_item_count": 1,
        "xfail_item_count": 1,
        "xpass_item_count": 1,
        "failed_item_count": 0,
        "observed_nodeids_sha256": _NODEIDS_DIGEST,
        "report_sha256": "sha256:" + "7" * 64,
    }
    values.update(overrides)
    return build_regression_execution_observation(**values)


def verify(
    result: RegressionExecutionObservation,
    *,
    expected_run_id: str = _RUN_ID,
    expected_revision: int = 2,
    expected_pytest_args: tuple[str, ...] = ("-q",),
    expected_observer_backend: str = _OBSERVER_BACKEND,
    expected_observer_identity: str = _OBSERVER_IDENTITY,
    expected_git_sha: str = _GIT_SHA,
    expected_source_fingerprint: str = _SOURCE_FINGERPRINT,
    expected_execution_subject_digest: str = _SUBJECT_DIGEST,
    expected_regression_suite_id: str = _SUITE_ID,
    expected_node_count: int = 4,
    expected_nodeids_sha256: str = _NODEIDS_DIGEST,
) -> RegressionExecutionObservation | None:
    return verified_regression_execution_observation(
        result.model_dump(mode="json"),
        expected_run_id=expected_run_id,
        expected_revision=expected_revision,
        expected_pytest_args=expected_pytest_args,
        expected_observer_backend=expected_observer_backend,
        expected_observer_identity=expected_observer_identity,
        expected_git_sha=expected_git_sha,
        expected_source_fingerprint=expected_source_fingerprint,
        expected_execution_subject_digest=expected_execution_subject_digest,
        expected_regression_suite_id=expected_regression_suite_id,
        expected_node_count=expected_node_count,
        expected_nodeids_sha256=expected_nodeids_sha256,
    )


def test_canonical_regression_observation_is_self_validating() -> None:
    result = observation()

    assert result.schema_version == REGRESSION_EXECUTION_SCHEMA
    assert result.authority == TRUSTED_REGRESSION_EXECUTION_AUTHORITY
    assert result.execution_id.startswith("sha256:")
    assert result.observed_item_count == result.node_count
    assert verify(result) == result


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("authority", "target_process_report_v1"),
        ("run_id", "run-other"),
        ("change_revision", 3),
        ("pytest_args", ["-x"]),
        ("observer_identity", "sha256:" + "8" * 64),
        ("execution_subject_digest", "sha256:" + "9" * 64),
        ("regression_suite_id", "sha256:" + "a" * 64),
        ("nodeids_sha256", "sha256:" + "b" * 64),
        ("report_sha256", "sha256:" + "c" * 64),
        ("passed_item_count", 2),
    ],
)
def test_authority_field_mutation_requires_new_execution_identity(
    field: str,
    replacement: object,
) -> None:
    valid = observation()
    payload = valid.model_dump(mode="json")
    payload[field] = replacement

    with pytest.raises(ValueError, match=r"execution_id|counts|authority"):
        RegressionExecutionObservation.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("change_revision", True),
        ("collection_complete", 1),
        ("execution_complete", 1),
        ("report_complete", 1),
        ("child_exit_code", False),
        ("passed_item_count", True),
    ],
)
def test_authority_scalars_reject_boolean_integer_coercion(
    field: str,
    replacement: object,
) -> None:
    with pytest.raises(ValueError):
        observation(**{field: replacement})


def test_item_counts_must_reconcile_and_remain_bounded() -> None:
    with pytest.raises(ValueError, match="item counts are inconsistent"):
        observation(observed_item_count=5)
    with pytest.raises(ValueError):
        observation(
            node_count=10_001,
            observed_item_count=10_001,
            passed_item_count=10_001,
            skipped_item_count=0,
            xfail_item_count=0,
            xpass_item_count=0,
        )


def test_pytest_invocation_is_bounded_and_nul_free() -> None:
    with pytest.raises(ValueError, match="invalid value"):
        observation(pytest_args=("-q", "bad\x00arg"))
    with pytest.raises(ValueError, match="byte bound"):
        observation(pytest_args=("x" * 4097,))


def test_unknown_report_fields_are_rejected() -> None:
    valid = observation()
    payload = valid.model_dump(mode="json")
    payload["target_controlled_claim"] = True

    with pytest.raises(ValueError):
        RegressionExecutionObservation.model_validate(payload)


def test_positive_verification_rejects_cross_subject_replay() -> None:
    result = observation()

    assert verify(result, expected_run_id="run-other") is None
    assert verify(result, expected_revision=3) is None
    assert verify(result, expected_pytest_args=("-x",)) is None
    assert verify(result, expected_observer_backend="other-observer") is None
    assert verify(result, expected_observer_identity="sha256:" + "8" * 64) is None
    assert verify(result, expected_git_sha="9" * 40) is None
    assert verify(result, expected_source_fingerprint="sha256:" + "a" * 64) is None
    assert verify(result, expected_execution_subject_digest="sha256:" + "b" * 64) is None
    assert verify(result, expected_regression_suite_id="sha256:" + "c" * 64) is None
    assert verify(result, expected_node_count=5) is None
    assert verify(result, expected_nodeids_sha256="sha256:" + "d" * 64) is None


def test_positive_verification_requires_complete_zero_failure_full_coverage() -> None:
    assert verify(observation(collection_complete=False)) is None
    assert verify(observation(execution_complete=False)) is None
    assert verify(observation(report_complete=False)) is None
    assert verify(observation(child_exit_code=1)) is None
    assert verify(observation(pytest_returncode=1)) is None
    assert verify(observation(failed_item_count=1, skipped_item_count=0)) is None
    assert verify(observation(passed_item_count=0, skipped_item_count=2)) is None
    assert verify(observation(node_count=5), expected_node_count=5) is None
    assert verify(observation(observed_nodeids_sha256="sha256:" + "e" * 64)) is None


def test_observer_identity_fields_are_canonical() -> None:
    with pytest.raises(ValueError):
        observation(run_id="run observer")
    with pytest.raises(ValueError):
        observation(observer_backend="Controller Observer")
    with pytest.raises(ValueError):
        observation(source_fingerprint="not-a-digest")
