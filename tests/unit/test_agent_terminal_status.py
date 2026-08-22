from pathlib import Path

from ai_qa_automation.agent import determine_terminal_outcome
from ai_qa_automation.models import TerminalStatus, ValidationResult, ValidationStatus


def vr(
    name: str,
    status: ValidationStatus,
    *,
    gate_id: str | None = None,
    revision: int = 0,
    scope: str | None = None,
) -> ValidationResult:
    return ValidationResult(
        name=name,
        gate_id=gate_id,
        revision=revision,
        status=status,
        summary=name,
        details={"scope": scope} if scope else {},
    )


def test_success_requires_nonempty_all_pass_validation_set() -> None:
    status, _ = determine_terminal_outcome("success", [vr("pytest", ValidationStatus.PASS)])
    assert status is TerminalStatus.SUCCESS

    status, _ = determine_terminal_outcome("success", [])
    assert status is TerminalStatus.NOT_VERIFIED


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


def test_new_change_revision_can_supersede_reproduced_failure_only_with_closure_gates() -> None:
    validations = [
        vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
        vr("test_patch_safety", ValidationStatus.PASS, gate_id="test_patch_safety:tests/test_x.py", revision=1),
        vr("pytest", ValidationStatus.PASS, gate_id="pytest:target", revision=1, scope="targeted"),
        vr("pytest", ValidationStatus.PASS, gate_id="pytest:regression", revision=1, scope="regression"),
    ]
    status, reason = determine_terminal_outcome(
        "success", validations, current_revision=1
    )
    assert status is TerminalStatus.SUCCESS
    assert "historical failures" in reason.lower()


def test_changed_revision_without_rerunning_original_failed_gate_stays_failure() -> None:
    validations = [
        vr("pytest", ValidationStatus.FAIL, gate_id="pytest:target", revision=0),
        vr("test_patch_safety", ValidationStatus.PASS, gate_id="test_patch_safety:tests/test_x.py", revision=1),
        vr("pytest", ValidationStatus.PASS, gate_id="pytest:regression", revision=1, scope="regression"),
    ]
    status, reason = determine_terminal_outcome(
        "success", validations, current_revision=1
    )
    assert status is TerminalStatus.FAILURE
    assert "pytest:target" in reason


def test_incomplete_validation_is_not_success() -> None:
    status, _ = determine_terminal_outcome(
        "success", [vr("mobile", ValidationStatus.NOT_VERIFIED)]
    )
    assert status is TerminalStatus.NOT_VERIFIED


def test_runtime_roots_reject_target_as_control_root(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    (tmp_path / ".claude").mkdir()
    (tmp_path / "CLAUDE.md").write_text("trusted")
    (tmp_path / ".claude" / "settings.json").write_text("{}")
    try:
        validate_runtime_roots(tmp_path, tmp_path)
    except ValueError as exc:
        assert "disjoint" in str(exc)
    else:
        raise AssertionError("target workspace must never become control_root")


def test_runtime_roots_require_trusted_project_markers(tmp_path: Path) -> None:
    from ai_qa_automation.agent import validate_runtime_roots

    control = tmp_path / "control"
    target = tmp_path / "target"
    control.mkdir()
    target.mkdir()
    try:
        validate_runtime_roots(control, target)
    except ValueError as exc:
        assert "CLAUDE.md" in str(exc)
    else:
        raise AssertionError("missing control-plane markers must fail closed")


def test_configuration_fingerprint_changes_with_runtime_settings(tmp_path: Path) -> None:
    from ai_qa_automation.agent import configuration_fingerprint
    from ai_qa_automation.config import Settings

    first = Settings(control_root=tmp_path, max_turns=3)
    second = Settings(control_root=tmp_path, max_turns=4)
    assert configuration_fingerprint(first).startswith("sha256:")
    assert configuration_fingerprint(first) != configuration_fingerprint(second)
