from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools.validation import ValidationGate


def test_gate_requires_real_checks_and_propagates_failure() -> None:
    gate = ValidationGate().add("pass", lambda: (True, "ok")).add("fail", lambda: (False, "bad"))
    results = gate.run()
    assert [r.status for r in results] == [ValidationStatus.PASS, ValidationStatus.FAIL]
    assert gate.all_passed(results) is False


def test_empty_gate_is_not_pass() -> None:
    assert ValidationGate.all_passed([]) is False
