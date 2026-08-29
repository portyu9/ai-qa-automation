from __future__ import annotations

from pathlib import Path
from typing import Any

EXPECTED_JSON_INSTANCE = '{"value":4}'
EXPECTED_JSON_SCHEMA = (
    '{"type":"object","properties":{"value":{"const":4}},'
    '"required":["value"],"additionalProperties":false}'
)
EXPECTED_GATE_ID = "json_schema:595df4bb4946b311"
EXPECTED_TERMINAL_SUMMARY = (
    "Agent completed with passing deterministic checks, but the operator did not supply an exact "
    "objective-validation gate contract."
)


def live_smoke_artifact_root(workspace: Path) -> Path:
    """Return a sibling artifact root so the smoke preserves runtime trust-root separation."""

    return workspace.parent / f"{workspace.name}-artifacts"


def assert_live_agent_smoke_contract(result: dict[str, Any]) -> None:
    """Fail closed unless live provider plumbing exercised one safe deterministic tool path."""

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
    assert validation.get("name") == "json_schema"
    assert validation.get("gate_id") == EXPECTED_GATE_ID
    assert validation.get("revision") == 0
    assert validation.get("status") == "PASS"
    assert validation.get("summary") == "Payload matches JSON Schema."
    assert validation.get("evidence_ids") == []
    assert validation.get("details") == {}
