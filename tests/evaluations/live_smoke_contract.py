from __future__ import annotations

from typing import Any

EXPECTED_PYTEST_ARGS = ["test_sample.py"]
EXPECTED_TERMINAL_SUMMARY = (
    "Agent completed with passing deterministic checks, but the operator did not supply an exact "
    "objective-validation gate contract."
)


def assert_live_agent_smoke_contract(result: dict[str, Any]) -> None:
    """Fail closed unless the live smoke exercised the intended deterministic pytest path."""

    report = result.get("report")
    assert isinstance(report, dict), "live smoke must return a structured report"
    assert report.get("terminal_status") == "NOT_VERIFIED"
    assert report.get("summary") == EXPECTED_TERMINAL_SUMMARY
    assert report.get("files_modified") == []

    provenance = report.get("provenance")
    assert isinstance(provenance, dict), "live smoke report must include provenance"
    assert provenance.get("objective_gate_id") == "NOT_SUPPLIED"

    validations = report.get("validation_results")
    assert isinstance(validations, list), "live smoke validations must be a list"
    assert len(validations) == 1, "live smoke must produce exactly one deterministic validation"

    validation = validations[0]
    assert isinstance(validation, dict), "live smoke validation must be structured"
    assert validation.get("name") == "pytest"
    gate_id = validation.get("gate_id")
    assert isinstance(gate_id, str) and gate_id.startswith("pytest:")
    assert validation.get("revision") == 0
    assert validation.get("status") == "PASS"
    assert validation.get("summary") == "pytest exited with 0"

    evidence_ids = validation.get("evidence_ids")
    assert isinstance(evidence_ids, list) and evidence_ids
    assert all(isinstance(item, str) and item for item in evidence_ids)

    details = validation.get("details")
    assert isinstance(details, dict), "live smoke pytest validation must include details"
    assert details.get("scope") == "targeted"
    assert details.get("args") == EXPECTED_PYTEST_ARGS
