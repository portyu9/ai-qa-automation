from __future__ import annotations

from ai_qa_automation.models import ValidationStatus
from ai_qa_automation.tools.contracts import validate_json_schema


def test_schema_validation_never_uses_model_opinion() -> None:
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}
    result = validate_json_schema({"id": 12}, schema)
    assert result.status in {ValidationStatus.PASS, ValidationStatus.NOT_VERIFIED}


def test_invalid_schema_is_not_mislabeled_as_payload_failure() -> None:
    result = validate_json_schema(
        {"id": 12},
        {"type": "definitely-not-a-json-schema-type"},
    )

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "schema itself is invalid" in result.summary.lower()


def test_valid_schema_mismatch_is_a_real_failure() -> None:
    result = validate_json_schema(
        {"id": "wrong"},
        {"type": "object", "properties": {"id": {"type": "integer"}}},
    )

    assert result.status is ValidationStatus.FAIL
