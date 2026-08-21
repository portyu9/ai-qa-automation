from __future__ import annotations

from typing import Any

from ..models import ValidationResult, ValidationStatus


def validate_json_schema(instance: Any, schema: dict[str, Any]) -> ValidationResult:
    """Validate API payloads deterministically when jsonschema is installed."""
    try:
        import jsonschema
    except ImportError:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="jsonschema optional dependency is not installed.",
        )
    try:
        jsonschema.validate(instance=instance, schema=schema)
    except jsonschema.ValidationError as exc:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.FAIL,
            summary=f"Schema mismatch at {'/'.join(str(p) for p in exc.path) or '<root>'}: {exc.message}",
        )
    return ValidationResult(name="json_schema", status=ValidationStatus.PASS, summary="Payload matches JSON Schema.")
