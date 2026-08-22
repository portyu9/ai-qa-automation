from __future__ import annotations

import pytest

from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools.validation import ValidationGate


def test_gate_requires_real_checks_and_propagates_failure() -> None:
    gate = ValidationGate().add("pass", lambda: (True, "ok")).add("fail", lambda: (False, "bad"))
    results = gate.run()
    assert [r.status for r in results] == [ValidationStatus.PASS, ValidationStatus.FAIL]
    assert gate.all_passed(results) is False


def test_empty_gate_is_not_pass() -> None:
    assert ValidationGate.all_passed([]) is False


@pytest.mark.parametrize("value", [1, "yes", [], object()])
def test_truthy_non_boolean_checker_outcome_is_not_verified(value: object) -> None:
    gate = ValidationGate().add("strict", lambda: (value, "looks green"))  # type: ignore[arg-type]

    result = gate.run()[0]

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "literal boolean" in result.summary


def test_checker_exception_is_not_mislabeled_as_assertion_failure() -> None:
    def broken() -> tuple[bool, str]:
        raise RuntimeError("validator infrastructure broke")

    result = ValidationGate().add("broken", broken).run()[0]

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "RuntimeError" in result.summary


def test_empty_or_non_string_checker_summary_is_not_verified() -> None:
    empty = ValidationGate().add("empty", lambda: (True, "")).run()[0]
    wrong_type = ValidationGate().add("wrong", lambda: (True, None)).run()[0]  # type: ignore[arg-type]

    assert empty.status is ValidationStatus.NOT_VERIFIED
    assert wrong_type.status is ValidationStatus.NOT_VERIFIED


def test_gate_name_must_be_nonempty() -> None:
    with pytest.raises(ValueError, match="name"):
        ValidationGate().add("   ", lambda: (True, "ok"))
