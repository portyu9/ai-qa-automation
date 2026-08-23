from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.agent import determine_terminal_outcome
from ai_qa_automation.models import TerminalStatus, ValidationResult, ValidationStatus


def vr(
    name: str,
    status: ValidationStatus,
    *,
    gate_id: str | None = None,
    revision: int = 0,
    scope: str | None = None,
    mutation_path: str = "tests/test_x.py",
    mutation_target_bound: bool = True,
    objective_bound: bool = False,
) -> ValidationResult:
    details: dict[str, object] = {}
    if name == "test_patch_safety" and revision > 0:
        details["path"] = mutation_path
    if scope:
        details["scope"] = scope
    if scope == "targeted" and revision > 0:
        details.update(
            {
                "args": [mutation_path],
                "mutation_target": mutation_path,
                "mutation_target_bound": mutation_target_bound,
            }
        )
    if scope == "regression":
        details["args"] = []
    if objective_bound:
        details["objective_bound"] = True
    return ValidationResult(
        name=name,
        gate_id=gate_id,
        revision=revision,
        status=status,
        summary=name,
        details=details,
    )


def test_read_only_success_requires_objective_bound_deterministic_validation() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [vr("pytest", ValidationStatus.PASS)],
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "deterministically bound" in reason.lower()

    status, _ = determine_terminal_outcome(
        "success",
        [vr("pytest", ValidationStatus.PASS, objective_bound=True)],
    )
    assert status is TerminalStatus.SUCCESS


def test_success_requires_nonempty_validation_set() -> None:
    status, reason = determine_terminal_outcome("success", [])
    assert status is TerminalStatus.NOT_VERIFIED
    assert "no deterministic validation" in reason.lower()


def test_non_success_model_subtype_cannot_be_overridden_by_green_validations() -> None:
    status, reason = determine_terminal_outcome(
        "error",
        [vr("pytest", ValidationStatus.PASS, gate_id="pytest:target")],
    )
    assert status is TerminalStatus.FAILURE
    assert "error" in reason


def test_missing_model_result_subtype_is_failure_not_optimistic_success() -> None:
    status, reason = determine_terminal_outcome(
        None,
        [vr("pytest", ValidationStatus.PASS)],
    )
    assert status is TerminalStatus.FAILURE
    assert "unknown" in reason.lower()


def test_same_revision_retry_cannot_hide_failure() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [
            vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
            vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=0),
        ],
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "flakiness" in reason.lower()


def test_same_revision_pass_then_fail_is_also_not_verified() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [
            vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=0),
            vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
        ],
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "pytest:target" in reason


def test_newer_failed_revision_dominates_older_pass_for_same_gate() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [
            vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=0),
            vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=1),
        ],
        current_revision=1,
    )
    assert status is TerminalStatus.FAILURE
    assert "pytest:target" in reason


def test_new_change_revision_can_supersede_reproduced_failure_only_with_closure_gates() -> None:
    validations = [
        vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
        vr(
            "test_patch_safety",
            ValidationStatus.PASS,
            gate_id="test_patch_safety:tests/test_x.py",
            revision=1,
        ),
        vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=1, scope="targeted"),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:regression",
            revision=1,
            scope="regression",
        ),
    ]
    status, reason = determine_terminal_outcome("success", validations, current_revision=1)
    assert status is TerminalStatus.SUCCESS
    assert "historical failures" in reason.lower()


def test_changed_revision_without_rerunning_original_failed_gate_stays_failure() -> None:
    validations = [
        vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
        vr(
            "test_patch_safety",
            ValidationStatus.PASS,
            gate_id="test_patch_safety:tests/test_x.py",
            revision=1,
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:regression",
            revision=1,
            scope="regression",
        ),
    ]
    status, reason = determine_terminal_outcome("success", validations, current_revision=1)
    assert status is TerminalStatus.FAILURE
    assert "pytest:target" in reason


@pytest.mark.parametrize(
    "incomplete",
    [
        ValidationStatus.NOT_VERIFIED,
        ValidationStatus.NOT_EXECUTED,
        ValidationStatus.NOT_OBSERVED,
        ValidationStatus.BLOCKED,
    ],
)
def test_incomplete_validation_states_are_never_success(incomplete: ValidationStatus) -> None:
    status, reason = determine_terminal_outcome("success", [vr("gate", incomplete)])
    assert status is TerminalStatus.NOT_VERIFIED
    assert incomplete.value in reason


def test_changed_revision_without_any_current_revision_gate_is_not_verified() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=0)],
        current_revision=1,
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "current change revision" in reason.lower()


def test_changed_revision_requires_current_pytest_gate() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [
            vr(
                "test_patch_safety",
                ValidationStatus.PASS,
                gate_id="test_patch_safety:tests/test_x.py",
                revision=1,
            )
        ],
        current_revision=1,
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "pytest" in reason.lower()


def test_changed_revision_requires_patch_safety_even_when_pytest_is_green() -> None:
    status, reason = determine_terminal_outcome(
        "success",
        [
            vr(
                "pytest",
                ValidationStatus.PASS,
                gate_id="pytest:target",
                revision=1,
                scope="targeted",
            ),
            vr(
                "pytest",
                ValidationStatus.PASS,
                gate_id="pytest:regression",
                revision=1,
                scope="regression",
            ),
        ],
        current_revision=1,
    )
    assert status is TerminalStatus.NOT_VERIFIED
    assert "patch-safety" in reason.lower()


@pytest.mark.parametrize("missing_scope", ["targeted", "regression"])
def test_changed_revision_requires_both_targeted_and_regression_pytest(
    missing_scope: str,
) -> None:
    present_scope = "regression" if missing_scope == "targeted" else "targeted"
    validations = [
        vr(
            "test_patch_safety",
            ValidationStatus.PASS,
            gate_id="test_patch_safety:tests/test_x.py",
            revision=1,
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id=f"pytest:{present_scope}",
            revision=1,
            scope=present_scope,
        ),
    ]
    status, reason = determine_terminal_outcome("success", validations, current_revision=1)
    assert status is TerminalStatus.NOT_VERIFIED
    assert "targeted" in reason.lower()
    assert "regression" in reason.lower()


def test_changed_revision_rejects_unbound_targeted_validation() -> None:
    validations = [
        vr(
            "test_patch_safety",
            ValidationStatus.PASS,
            gate_id="test_patch_safety:tests/test_x.py",
            revision=1,
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:target",
            revision=1,
            scope="targeted",
            mutation_target_bound=False,
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:regression",
            revision=1,
            scope="regression",
        ),
    ]

    status, reason = determine_terminal_outcome("success", validations, current_revision=1)
    assert status is TerminalStatus.NOT_VERIFIED
    assert "exact-path-bound" in reason


def test_changed_revision_rejects_mismatched_patch_and_targeted_paths() -> None:
    validations = [
        vr(
            "test_patch_safety",
            ValidationStatus.PASS,
            gate_id="test_patch_safety:tests/test_x.py",
            revision=1,
            mutation_path="tests/test_x.py",
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:target",
            revision=1,
            scope="targeted",
            mutation_path="tests/test_other.py",
        ),
        vr(
            "pytest",
            ValidationStatus.PASS,
            gate_id="pytest:regression",
            revision=1,
            scope="regression",
        ),
    ]

    status, _ = determine_terminal_outcome("success", validations, current_revision=1)
    assert status is TerminalStatus.NOT_VERIFIED


def test_runtime_roots_reject_target_as_control_root(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    (tmp_path / ".claude").mkdir()
    (tmp_path / "CLAUDE.md").write_text("trusted", encoding="utf-8")
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="disjoint"):
        validate_runtime_roots(tmp_path, tmp_path)


def test_runtime_roots_reject_nested_target_or_control_root(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    control = tmp_path / "control"
    target = control / "target"
    (control / ".claude").mkdir(parents=True)
    target.mkdir()
    (control / "CLAUDE.md").write_text("trusted", encoding="utf-8")
    (control / ".claude" / "settings.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="disjoint"):
        validate_runtime_roots(control, target)


def test_runtime_roots_reject_artifact_root_overlapping_target(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    control = tmp_path / "control"
    target = tmp_path / "target"
    (control / ".claude").mkdir(parents=True)
    target.mkdir()
    (control / "CLAUDE.md").write_text("trusted", encoding="utf-8")
    (control / ".claude" / "settings.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="artifact_root"):
        validate_runtime_roots(control, target, artifact_root=target / "artifacts")


def test_runtime_roots_require_trusted_project_markers(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()

    with pytest.raises(ValueError, match=r"CLAUDE\.md"):
        validate_runtime_roots(control, target)


def test_configuration_fingerprint_changes_with_security_relevant_settings(tmp_path: Path) -> None:
    from ai_qa_automation.agent import configuration_fingerprint
    from ai_qa_automation.config import Settings

    baseline = Settings(control_root=tmp_path, max_turns=3)
    changed_turns = Settings(control_root=tmp_path, max_turns=4)
    changed_writes = Settings(control_root=tmp_path, max_turns=3, allow_test_writes=True)
    changed_hosts = Settings(
        control_root=tmp_path,
        max_turns=3,
        allowed_network_hosts=["127.0.0.1", "qa.example.test"],
    )

    fingerprints = {
        configuration_fingerprint(baseline),
        configuration_fingerprint(changed_turns),
        configuration_fingerprint(changed_writes),
        configuration_fingerprint(changed_hosts),
    }
    assert all(value.startswith("sha256:") for value in fingerprints)
    assert len(fingerprints) == 4


def test_configuration_fingerprint_is_stable_for_equivalent_settings(tmp_path: Path) -> None:
    from ai_qa_automation.agent import configuration_fingerprint
    from ai_qa_automation.config import Settings

    first = Settings(control_root=tmp_path, max_turns=7, max_network_calls=4)
    second = Settings(control_root=tmp_path, max_turns=7, max_network_calls=4)
    assert configuration_fingerprint(first) == configuration_fingerprint(second)
