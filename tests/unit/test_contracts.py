from __future__ import annotations

import json
from pathlib import Path

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


def test_unknown_explicit_schema_dialect_is_not_reinterpreted() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://unknown.example/schema",
            "type": "integer",
        },
    )

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "unsupported schema dialect" in result.summary


def test_malformed_schema_dialect_identifier_is_not_verified() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": 202012,
            "type": "integer",
        },
    )

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "malformed schema dialect" in result.summary


def test_same_document_reference_remains_deterministic() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {"integer": {"type": "integer"}},
            "$ref": "#/$defs/integer",
        },
    )

    assert result.status is ValidationStatus.PASS


def test_embedded_resource_reference_remains_deterministic() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {
                "integer": {
                    "$id": "urn:aiqa:integer",
                    "type": "integer",
                }
            },
            "$ref": "urn:aiqa:integer",
        },
    )

    assert result.status is ValidationStatus.PASS


def test_file_reference_cannot_read_local_schema_resource(tmp_path: Path) -> None:
    external = tmp_path / "external-schema.json"
    external.write_text(json.dumps({"const": "outside-resource"}), encoding="utf-8")

    result = validate_json_schema(
        "outside-resource",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": external.as_uri(),
        },
    )

    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "file"}


def test_remote_reference_is_blocked_without_persisting_secret_uri() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "https://example.invalid/schema.json?token=super-secret-token",
        },
    )

    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "https"}
    assert "super-secret-token" not in result.model_dump_json()


def test_relative_external_reference_is_blocked() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "other-schema.json",
        },
    )

    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "relative"}


def test_external_dynamic_reference_is_blocked() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$dynamicRef": "https://example.invalid/dynamic-schema.json",
        },
    )

    assert result.status is ValidationStatus.BLOCKED
    assert result.details == {"reference_scheme": "https"}


def test_unresolved_same_document_reference_is_not_verified() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/missing",
        },
    )

    assert result.status is ValidationStatus.NOT_VERIFIED
    assert "cannot be resolved within the supplied schema" in result.summary


def test_ref_shaped_literal_data_does_not_trigger_reference_policy() -> None:
    literal = {"$ref": "https://example.invalid/not-a-schema-reference"}

    result = validate_json_schema(
        literal,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "const": literal,
        },
    )

    assert result.status is ValidationStatus.PASS
