from __future__ import annotations

import pytest

from ai_qa_automation.runtime.targeted_execution_observer import (
    TARGETED_EXECUTION_SCHEMA,
    TargetedExecutionObservation,
    build_targeted_execution_observation,
)


def observation(**overrides: object) -> TargetedExecutionObservation:
    values: dict[str, object] = {
        "schema_version": TARGETED_EXECUTION_SCHEMA,
        "run_id": "run-observer-contract",
        "change_revision": 2,
        "mutation_path": "tests/test_changed.py",
        "pytest_args": ("tests/test_changed.py::test_changed", "-q"),
        "observer_backend": "controller-observer-test-double",
        "observer_identity": "sha256:" + "1" * 64,
        "git_sha": "2" * 40,
        "source_fingerprint": "sha256:" + "3" * 64,
        "execution_subject_digest": "sha256:" + "4" * 64,
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


def test_canonical_observation_is_self_validating() -> None:
    result = observation()

    assert result.schema_version == TARGETED_EXECUTION_SCHEMA
    assert result.execution_id.startswith("sha256:")
    assert result.run_id == "run-observer-contract"
    assert result.change_revision == 2
    assert result.passed_paths == ("tests/test_changed.py",)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
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

    with pytest.raises(ValueError, match="execution_id|counts"):
        TargetedExecutionObservation.model_validate(payload)


def test_call_phase_counts_must_reconcile_exactly() -> None:
    with pytest.raises(ValueError, match="counts are inconsistent"):
        observation(call_report_count=4)


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
