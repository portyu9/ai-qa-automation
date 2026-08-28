from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..models import ValidationResult, ValidationStatus


def validate_json_schema(instance: Any, schema: dict[str, Any]) -> ValidationResult:
    """Validate one supplied JSON Schema without granting reference-retrieval authority."""
    try:
        import jsonschema
        from jsonschema.validators import validator_for
        from referencing import Registry
        from referencing.exceptions import NoSuchResource, Unresolvable
    except ImportError:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="jsonschema optional dependency is not installed.",
        )

    dialect = schema.get("$schema")
    if dialect is not None and not isinstance(dialect, str):
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema declares a malformed schema dialect identifier.",
        )
    if dialect is None:
        validator_class = validator_for(schema)
    else:
        validator_class = validator_for(schema, default=None)
        if validator_class is None:
            return ValidationResult(
                name="json_schema",
                status=ValidationStatus.NOT_VERIFIED,
                summary="JSON Schema declares an unsupported schema dialect.",
            )

    retrieval_attempts: list[str] = []

    def deny_external_reference(uri: str) -> Any:
        retrieval_attempts.append(str(uri))
        raise NoSuchResource(ref=uri)

    try:
        validator_class.check_schema(schema)
        validator = validator_class(
            schema,
            registry=Registry(retrieve=deny_external_reference),
        )
        validator.validate(instance)
    except jsonschema.SchemaError as exc:
        path = "/".join(str(part) for part in exc.path) or "<root>"
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary=f"JSON Schema itself is invalid at {path}; payload validity was not proven.",
            details={"schema_path": path, "validator": str(exc.validator)},
        )
    except jsonschema.ValidationError as exc:
        path = "/".join(str(part) for part in exc.path) or "<root>"
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.FAIL,
            summary=f"Schema mismatch at {path} (validator={exc.validator}).",
            details={"path": path, "validator": str(exc.validator)},
        )
    except Unresolvable:
        if retrieval_attempts:
            scheme = urlparse(retrieval_attempts[-1]).scheme.casefold() or "relative"
            return ValidationResult(
                name="json_schema",
                status=ValidationStatus.BLOCKED,
                summary=(
                    "JSON Schema external reference retrieval is disabled by deterministic policy."
                ),
                details={"reference_scheme": scheme},
            )
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary=(
                "JSON Schema contains a reference that cannot be resolved within the supplied schema."
            ),
        )
    return ValidationResult(
        name="json_schema",
        status=ValidationStatus.PASS,
        summary="Payload matches JSON Schema.",
    )
