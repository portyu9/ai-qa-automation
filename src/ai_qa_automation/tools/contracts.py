from __future__ import annotations

import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from types import FrameType
from typing import Any
from urllib.parse import urlparse

from ..models import ValidationResult, ValidationStatus

_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS = 2.0


class _SchemaValidationTimeout(RuntimeError):
    pass


class _SchemaValidationTimerUnavailable(RuntimeError):
    pass


def _schema_validation_timer_supported() -> bool:
    return (
        hasattr(signal, "setitimer")
        and hasattr(signal, "getitimer")
        and hasattr(signal, "ITIMER_REAL")
        and hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )


def _raise_schema_validation_timeout(_signum: int, _frame: FrameType | None) -> None:
    raise _SchemaValidationTimeout("JSON Schema validation exceeded its execution budget")


@contextmanager
def _schema_validation_budget() -> Iterator[None]:
    if not _schema_validation_timer_supported():
        raise _SchemaValidationTimerUnavailable(
            "deterministic JSON Schema validation timer is unavailable in this runtime"
        )

    remaining, interval = signal.getitimer(signal.ITIMER_REAL)
    if remaining > 0 or interval > 0:
        raise _SchemaValidationTimerUnavailable(
            "process interval-timer authority is already owned by another runtime component"
        )

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _raise_schema_validation_timeout)
    try:
        signal.setitimer(signal.ITIMER_REAL, _JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, previous_handler)


def validate_json_schema(instance: Any, schema: dict[str, Any]) -> ValidationResult:
    """Validate one supplied JSON Schema without granting ambient authority."""
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
        with _schema_validation_budget():
            validator_class.check_schema(schema)
            validator = validator_class(
                schema,
                registry=Registry(retrieve=deny_external_reference),
            )
            validator.validate(instance)
    except _SchemaValidationTimerUnavailable as exc:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.BLOCKED,
            summary=f"JSON Schema validation is blocked: {exc}.",
        )
    except _SchemaValidationTimeout:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary=(
                "JSON Schema validation exceeded its deterministic execution-time budget."
            ),
            details={"timeout_seconds": _JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS},
        )
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
