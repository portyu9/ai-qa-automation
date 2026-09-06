from __future__ import annotations

import pytest

from ai_qa_automation.runtime.targeted_execution_observer import (
    TARGETED_EXECUTION_SCHEMA,
    TRUSTED_TARGETED_EXECUTION_AUTHORITY,
    TargetedExecutionObservation,
    build_targeted_execution_observation,
    verified_targeted_execution_observation,
)

_OBSERVER_BACKEND = "controller-observer-test-double"
_OBSERVER_IDENTITY = "sha256:" + "1" * 64
_GIT_SHA = "2" * 40
_SOURCE_FINGERPRINT = "sha256:" + "3" * 64
_SUBJECT_DIGEST = "sha256:" + "4" * 64


def observation(**overrides: object) -> TargetedExecutionObservation:
    values: dict[str, object] = {
        "schema_version": TARGETED_EXECUTION_SCHEMA,
        "authority": TRUSTED_TARGETED_EXECUTION_AUTHORITY,
        "run_id": "run-observer-contract",
        "change_revision": 2,
        "mutation_path": "tests/test_changed.py",
        "pytest_args": ("tests/test_changed.py::test_changed", "-q"),
        "observer_backend": _OBSERVER_BACKEND,
        "observer_identity": _OBSERVER_IDENTITY,
        "git_sha": _GIT_SHA,
        "source_fingerprint": _SOURCE_FINGERPRINT,
        "execution_subject_digest": _SUBJECT_DIGEST,
        "report_complete": True,
        "child_exit_code": 0,
        "pytest_returncode": 0,
        "call_report_count": 3,
        "passed_call_count": 1,
        "skipped_call_count": 1,
        "xfail_call_count": 1,
        "failed_call_count": 0,
        "passed_paths": ("tests/test_changed.py",),
        "report_sha256": "sha256:" + "5" * 64,
    }
    values.update(overrides)
    return build_targeted_execution_observation(**values)


def verify(
    result: TargetedExecutionObservation,
    **expected_overrides: object,
) -> TargetedExecutionObservation | None:
    expected: dict[str, object] = {
        "expected_run_id": "run-observer-contract",
        "expected_revision": 2,
        "expected_mutation_path": "tests/test_changed.py",
        "expected_pytest_args": ("tests/test_changed.py::test_changed", "-q"),
        "expected_observer_backend": _OBSERVER_BACKEND,
        "expected_observer_identity": _OBSERVER_IDENTITY,
        "expected_git_sha": _GIT_SHA,
        "expected_source_fingerprint": _SOURCE_FINGERPRINT,
        "expected_execution_subject_digest": _SUBJECT_DIGEST,
    }
    expected.update(expected_overrides)
    return verified_targeted_execution_observation(
        result.model_dump(mode="json"),
        expected_run_id=str(expected["expected_run_id"]),
        expected_revision=int(expected["expected_revision"]),
        expected_mutation_path=str(expected["expected_mutation_path"]),
        expected_pytest_args=tuple(expected["expected_pytest_args"]),
        expected_observer_backend=str(expected["expected_observer_backend"]),
        expected_observer_identity=str(expected["expected_observer_identity"]),
        expected_git_sha=str(expected["expected_git_sha"]),
        expected_source_fingerprint=str(expected["expected_source_fingerprint"]),
        expected_execution_subject_digest=str(expected["expected_execution_subject_digest"]),
    )


def test_canonical_observation_is_self_validating() -> None:
    result = observation()

    assert result.schema_version == TARGETED_EXECUTION_SCHEMA
    assert result.authority == TRUSTED_TARGETED_EXECUTION_AUTHORITY
    assert result.execution_id.startswith("sha256:")
    assert result.run_id == "run-observer-contract"
    assert result.change_revision == 2
    assert result.passed_paths == ("tests/test_changed.py",)
    assert verify(result) == result


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("authority", "target_process_report_v1"),
        ("run_id", "run-other"),
        ("change_revision", 3),
        ("mutation_path", "tests/test_other.py"),
        ("pytest_args", ["tests/test_other.py::test_other"]),
        ("observer_identity", "sha256:" + "6" * 64),
        ("execution_subject_digest", "sha256:" + "7" * 64),
        ("report_sha256", "sha256:" + "8" * 64),
        ("passed_call_count", 2),
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
        TargetedExecutionObservation.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("change_revision", True),
        ("report_complete", 1),
        ("child_exit_code", False),
        ("passed_call_count", True),
    ],
)
def test_authority_scalars_reject_boolean_integer_coercion(
    field: str,
    replacement: object,
) -> None:
    with pytest.raises(ValueError):
        observation(**{field: replacement})


def test_call_phase_counts_must_reconcile_and_remain_bounded() -> None:
    with pytest.raises(ValueError, match="counts are inconsistent"):
        observation(call_report_count=4)
    with pytest.raises(ValueError):
        observation(
            call_report_count=10_001,
            passed_call_count=10_001,
            skipped_call_count=0,
            xfail_call_count=0,
        )


def test_passed_paths_must_be_canonical_unique_and_bounded() -> None:
    with pytest.raises(ValueError, match="not canonical"):
        observation(passed_paths=("../escape.py",))
    with pytest.raises(ValueError, match="must be unique"):
        observation(
            passed_call_count=2,
            call_report_count=4,
            passed_paths=("tests/test_changed.py", "tests/test_changed.py"),
        )
    with pytest.raises(ValueError):
        observation(
            passed_call_count=5,
            call_report_count=7,
            passed_paths=("a.py", "b.py", "c.py", "d.py", "e.py"),
        )


def test_pytest_invocation_is_bounded_and_nul_free() -> None:
    with pytest.raises(ValueError, match="invalid value"):
        observation(pytest_args=("tests/test_changed.py", "bad\x00arg"))
    with pytest.raises(ValueError, match="byte bound"):
        observation(pytest_args=("x" * 4097,))


def test_unknown_report_fields_are_rejected() -> None:
    valid = observation()
    payload = valid.model_dump(mode="json")
    payload["target_controlled_claim"] = True

    with pytest.raises(ValueError):
        TargetedExecutionObservation.model_validate(payload)


def test_zero_pass_report_cannot_claim_passed_paths() -> None:
    with pytest.raises(ValueError, match="passed paths"):
        observation(
            passed_call_count=0,
            call_report_count=2,
            passed_paths=("tests/test_changed.py",),
        )


def test_positive_verification_rejects_cross_run_revision_and_command_replay() -> None:
    result = observation()

    assert verify(result, expected_run_id="run-other") is None
    assert verify(result, expected_revision=3) is None
    assert verify(result, expected_pytest_args=("tests/test_changed.py::test_other", "-q")) is None


def test_positive_verification_rejects_observer_or_execution_subject_mismatch() -> None:
    result = observation()

    assert verify(result, expected_observer_backend="other-observer") is None
    assert verify(result, expected_observer_identity="sha256:" + "6" * 64) is None
    assert verify(result, expected_git_sha="7" * 40) is None
    assert verify(result, expected_source_fingerprint="sha256:" + "8" * 64) is None
    assert verify(result, expected_execution_subject_digest="sha256:" + "9" * 64) is None


def test_positive_verification_requires_exact_mutation_selector_and_passed_path() -> None:
    unrelated_selector = observation(
        pytest_args=("tests/test_other.py::test_other", "-q"),
        passed_paths=("tests/test_changed.py",),
    )
    assert verify(unrelated_selector) is None

    unrelated_pass = observation(passed_paths=("tests/test_other.py",))
    assert verify(unrelated_pass) is None


def test_positive_verification_rejects_incomplete_failed_or_nonzero_reports() -> None:
    assert verify(observation(report_complete=False)) is None
    assert verify(observation(child_exit_code=1)) is None
    assert verify(observation(pytest_returncode=1)) is None
    assert (
        verify(
            observation(
                call_report_count=4,
                failed_call_count=1,
            )
        )
        is None
    )


def test_observer_identity_fields_are_canonical() -> None:
    with pytest.raises(ValueError):
        observation(run_id="run observer")
    with pytest.raises(ValueError):
        observation(observer_backend="Controller Observer")
    with pytest.raises(ValueError):
        observation(source_fingerprint="not-a-digest")
