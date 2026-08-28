from __future__ import annotations

import json
import signal
import time
from pathlib import Path

import pytest

from ai_qa_automation.models import ValidationResult, ValidationStatus
from ai_qa_automation.tools import contracts
from ai_qa_automation.tools.contracts import validate_json_schema


def _assert_runtime_validation_status(
    result: ValidationResult,
    expected: ValidationStatus,
) -> bool:
    if contracts._schema_validation_timer_supported():
        assert result.status is expected
        return True
    assert result.status is ValidationStatus.BLOCKED
    assert "timer" in result.summary.lower()
    return False


def test_schema_validation_never_uses_model_opinion() -> None:
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}
    result = validate_json_schema({"id": 12}, schema)
    _assert_runtime_validation_status(result, ValidationStatus.PASS)


def test_invalid_schema_is_not_mislabeled_as_payload_failure() -> None:
    result = validate_json_schema(
        {"id": 12},
        {"type": "definitely-not-a-json-schema-type"},
    )

    if _assert_runtime_validation_status(result, ValidationStatus.NOT_VERIFIED):
        assert "schema itself is invalid" in result.summary.lower()


def test_valid_schema_mismatch_is_a_real_failure() -> None:
    result = validate_json_schema(
        {"id": "wrong"},
        {"type": "object", "properties": {"id": {"type": "integer"}}},
    )

    _assert_runtime_validation_status(result, ValidationStatus.FAIL)


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

    _assert_runtime_validation_status(result, ValidationStatus.PASS)


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

    _assert_runtime_validation_status(result, ValidationStatus.PASS)


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

    if _assert_runtime_validation_status(result, ValidationStatus.BLOCKED):
        assert result.details == {"reference_scheme": "file"}


def test_remote_reference_is_blocked_without_persisting_secret_uri() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "https://example.invalid/schema.json?token=super-secret-token",
        },
    )

    if _assert_runtime_validation_status(result, ValidationStatus.BLOCKED):
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

    if _assert_runtime_validation_status(result, ValidationStatus.BLOCKED):
        assert result.details == {"reference_scheme": "relative"}


def test_external_dynamic_reference_is_blocked() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$dynamicRef": "https://example.invalid/dynamic-schema.json",
        },
    )

    if _assert_runtime_validation_status(result, ValidationStatus.BLOCKED):
        assert result.details == {"reference_scheme": "https"}


def test_unresolved_same_document_reference_is_not_verified() -> None:
    result = validate_json_schema(
        12,
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/missing",
        },
    )

    if _assert_runtime_validation_status(result, ValidationStatus.NOT_VERIFIED):
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

    _assert_runtime_validation_status(result, ValidationStatus.PASS)


def test_pathological_pattern_cannot_run_unbounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS", 0.05)
    started = time.monotonic()

    result = validate_json_schema(
        "a" * 28 + "!",
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "string",
            "pattern": "(a+)+$",
        },
    )

    elapsed = time.monotonic() - started
    assert elapsed < 1.0
    if contracts._schema_validation_timer_supported():
        assert result.status is ValidationStatus.NOT_VERIFIED
        assert result.details == {"timeout_seconds": 0.05}
    else:
        assert result.status is ValidationStatus.BLOCKED


def test_combinatorial_schema_cannot_run_unbounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contracts, "_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS", 0.05)
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "anyOf": [{"const": value} for value in range(5_000)],
    }
    started = time.monotonic()

    result = validate_json_schema(-1, schema)

    elapsed = time.monotonic() - started
    assert elapsed < 1.0
    if contracts._schema_validation_timer_supported():
        assert result.status is ValidationStatus.NOT_VERIFIED
        assert result.details == {"timeout_seconds": 0.05}
    else:
        assert result.status is ValidationStatus.BLOCKED


def test_existing_interval_timer_is_not_overridden() -> None:
    if not contracts._schema_validation_timer_supported():
        result = validate_json_schema(12, {"type": "integer"})
        assert result.status is ValidationStatus.BLOCKED
        return

    prior_remaining, prior_interval = signal.getitimer(signal.ITIMER_REAL)
    if prior_remaining > 0 or prior_interval > 0:
        result = validate_json_schema(12, {"type": "integer"})
        assert result.status is ValidationStatus.BLOCKED
        return

    signal.setitimer(signal.ITIMER_REAL, 5.0)
    try:
        result = validate_json_schema(12, {"type": "integer"})
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

    assert result.status is ValidationStatus.BLOCKED
    assert remaining > 4.0
    assert interval == 0


def test_signal_handler_is_restored_after_schema_validation() -> None:
    if not contracts._schema_validation_timer_supported():
        return
    previous_handler = signal.getsignal(signal.SIGALRM)

    result = validate_json_schema(12, {"type": "integer"})

    assert result.status is ValidationStatus.PASS
    assert signal.getsignal(signal.SIGALRM) == previous_handler
