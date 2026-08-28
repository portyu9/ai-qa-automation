from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from typing import Any

from ..models import ValidationResult, ValidationStatus
from .execution_env import restricted_subprocess_env, run_bounded_subprocess

_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS = 2.0
_JSON_SCHEMA_WORKER_STARTUP_GRACE_SECONDS = 5.0
_MAX_JSON_SCHEMA_WORKER_INPUT_BYTES = 2_100_000
_MAX_JSON_SCHEMA_WORKER_OUTPUT_BYTES = 8_192
_SAFE_REFERENCE_SCHEMES = frozenset({"http", "https", "file", "ftp", "urn", "data", "relative", "other"})

_JSON_SCHEMA_WORKER_CODE = dedent(
    r"""
    import json
    import signal
    import sys
    from contextlib import contextmanager
    from urllib.parse import urlparse

    validation_timeout = float(sys.argv[2])
    sys.path.extend(sys.argv[3:])

    class ValidationTimeout(RuntimeError):
        pass

    def emit(kind, **details):
        sys.stdout.write(json.dumps({"kind": kind, **details}, sort_keys=True, separators=(",", ":")))
        sys.stdout.flush()

    def finish(kind, **details):
        emit(kind, **details)
        raise SystemExit(0)

    def raise_timeout(_signum, _frame):
        raise ValidationTimeout("schema evaluation timed out")

    @contextmanager
    def validation_budget():
        required = (
            hasattr(signal, "setitimer")
            and hasattr(signal, "getitimer")
            and hasattr(signal, "ITIMER_REAL")
            and hasattr(signal, "SIGALRM")
        )
        if not required:
            finish("budget_unavailable")
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        previous_handler = signal.getsignal(signal.SIGALRM)
        if remaining > 0 or interval > 0 or previous_handler != signal.SIG_DFL:
            finish("budget_unavailable")
        signal.signal(signal.SIGALRM, raise_timeout)
        try:
            signal.setitimer(signal.ITIMER_REAL, validation_timeout)
            try:
                yield
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)

    def reference_scheme(uri):
        raw = urlparse(str(uri)).scheme.casefold()
        if not raw:
            return "relative"
        if raw in {"http", "https", "file", "ftp", "urn", "data"}:
            return raw
        return "other"

    try:
        import jsonschema
        from jsonschema.validators import validator_for
        from referencing import Registry
        from referencing.exceptions import NoSuchResource, Unresolvable
        from referencing.jsonschema import specification_with
    except ImportError:
        finish("dependency_unavailable")

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as stream:
            payload = json.load(stream)
        instance = payload["instance"]
        schema = payload["schema"]
        retrieval_schemes = []
        if not isinstance(schema, (dict, bool)):
            finish("schema_error")

        with validation_budget():
            if isinstance(schema, dict):
                dialect = schema.get("$schema")
                if dialect is not None and not isinstance(dialect, str):
                    finish("malformed_dialect")
                if "$schema" in schema:
                    validator_class = validator_for(schema, default=None)
                    if validator_class is None:
                        finish("unsupported_dialect")
                else:
                    validator_class = validator_for(schema)

                validator_class.check_schema(schema)
                meta_id = validator_class.META_SCHEMA.get("$id") or validator_class.META_SCHEMA.get("id")
                if not isinstance(meta_id, str):
                    finish("worker_error")
                try:
                    specification = specification_with(meta_id)
                except Exception:
                    finish("worker_error")

                stack = list(specification.subresources_of(schema))
                while stack:
                    subresource = stack.pop()
                    if not isinstance(subresource, dict):
                        continue
                    nested_dialect = subresource.get("$schema")
                    if nested_dialect is not None:
                        if not isinstance(nested_dialect, str):
                            finish("malformed_embedded_dialect")
                        nested_validator = validator_for(subresource, default=None)
                        if nested_validator is None:
                            finish("unsupported_embedded_dialect")
                        if nested_validator is not validator_class:
                            finish("cross_dialect_resource")
                    stack.extend(specification.subresources_of(subresource))
            else:
                validator_class = validator_for(schema)
                validator_class.check_schema(schema)

            def deny_external_reference(uri):
                retrieval_schemes.append(reference_scheme(uri))
                raise NoSuchResource(ref=uri)

            validator = validator_class(schema, registry=Registry(retrieve=deny_external_reference))
            validator.validate(instance)
    except ValidationTimeout:
        finish("timeout")
    except jsonschema.SchemaError:
        finish("schema_error")
    except jsonschema.ValidationError:
        finish("validation_error")
    except Unresolvable:
        if retrieval_schemes:
            finish("external_reference", reference_scheme=retrieval_schemes[-1])
        finish("unresolved_internal_reference")
    except SystemExit:
        raise
    except Exception:
        finish("worker_error")
    finish("pass")
    """
).strip()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _isolated_dependency_roots() -> tuple[str, ...] | None:
    try:
        prefixes = {Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()}
    except OSError:
        return None
    roots: set[str] = set()
    for module_name in ("jsonschema", "referencing"):
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, AttributeError, ValueError):
            return None
        if spec is None or spec.origin in {None, "built-in", "frozen"}:
            return None
        try:
            origin = Path(str(spec.origin)).resolve(strict=True)
        except OSError:
            return None
        if not origin.is_file():
            return None
        package_root = origin.parent.parent
        if not package_root.is_dir():
            return None
        if not any(_is_within(package_root, prefix) for prefix in prefixes):
            return None
        roots.add(str(package_root))
    return tuple(sorted(roots))


class _WorkerInputError(ValueError):
    pass


def _write_worker_payload(path: Path, *, instance: Any, schema: Any) -> None:
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        allow_nan=False,
        check_circular=True,
        separators=(",", ":"),
    )
    total = 0
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            stream = os.fdopen(descriptor, "wb")
        except Exception:
            os.close(descriptor)
            raise
        with stream:
            for chunk in encoder.iterencode({"instance": instance, "schema": schema}):
                encoded = chunk.encode("utf-8")
                total += len(encoded)
                if total > _MAX_JSON_SCHEMA_WORKER_INPUT_BYTES:
                    raise _WorkerInputError("JSON Schema worker payload exceeds the byte limit")
                stream.write(encoded)
    except _WorkerInputError:
        raise
    except (TypeError, ValueError, RecursionError, UnicodeError, OverflowError) as exc:
        raise _WorkerInputError("JSON Schema worker payload is not bounded JSON") from exc


def validate_json_schema(instance: Any, schema: Any) -> ValidationResult:
    """Validate one bounded JSON Schema in an isolated, non-retrieving worker process."""
    dependency_roots = _isolated_dependency_roots()
    if dependency_roots is None:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema validation dependencies are unavailable to the isolated worker.",
        )

    try:
        with TemporaryDirectory(prefix="aiqa-json-schema-") as temporary:
            workspace = Path(temporary)
            payload_path = workspace / "payload.json"
            try:
                _write_worker_payload(payload_path, instance=instance, schema=schema)
            except _WorkerInputError:
                return ValidationResult(
                    name="json_schema",
                    status=ValidationStatus.NOT_VERIFIED,
                    summary="JSON Schema validation inputs exceed the bounded JSON worker contract.",
                )
            env = restricted_subprocess_env(home=workspace / "home")
            result = run_bounded_subprocess(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    _JSON_SCHEMA_WORKER_CODE,
                    str(payload_path),
                    str(_JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS),
                    *dependency_roots,
                ],
                cwd=workspace,
                env=env,
                timeout_seconds=(
                    _JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS
                    + _JSON_SCHEMA_WORKER_STARTUP_GRACE_SECONDS
                ),
                max_output_bytes=_MAX_JSON_SCHEMA_WORKER_OUTPUT_BYTES,
            )
    except (OSError, RuntimeError, ValueError):
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.BLOCKED,
            summary="Isolated JSON Schema validation worker could not be started or closed safely.",
        )

    if result.timed_out:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="Isolated JSON Schema worker exceeded its bounded process envelope.",
            details={
                "validation_timeout_seconds": _JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS,
                "startup_grace_seconds": _JSON_SCHEMA_WORKER_STARTUP_GRACE_SECONDS,
            },
        )
    if result.returncode != 0 or result.stdout_truncated:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="Isolated JSON Schema validation worker did not produce a complete result.",
        )
    try:
        worker_result = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        worker_result = None
    if not isinstance(worker_result, dict) or not isinstance(worker_result.get("kind"), str):
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="Isolated JSON Schema validation worker returned an invalid result envelope.",
        )

    kind = worker_result["kind"]
    if kind == "timeout":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema evaluation exceeded its deterministic execution-time budget.",
            details={"timeout_seconds": _JSON_SCHEMA_VALIDATION_TIMEOUT_SECONDS},
        )
    if kind == "budget_unavailable":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.BLOCKED,
            summary="Isolated JSON Schema evaluation timer is unavailable or already owned.",
        )
    if kind == "pass":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.PASS,
            summary="Payload matches JSON Schema.",
        )
    if kind == "validation_error":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.FAIL,
            summary="Payload does not match JSON Schema.",
        )
    if kind == "external_reference":
        scheme = worker_result.get("reference_scheme")
        if not isinstance(scheme, str) or scheme not in _SAFE_REFERENCE_SCHEMES:
            scheme = "other"
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.BLOCKED,
            summary="JSON Schema external reference retrieval is disabled by deterministic policy.",
            details={"reference_scheme": scheme},
        )
    if kind == "unresolved_internal_reference":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema contains a reference that cannot be resolved within supplied resources.",
        )
    if kind == "dependency_unavailable":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema validation dependencies are unavailable to the isolated worker.",
        )
    if kind in {
        "malformed_dialect",
        "unsupported_dialect",
        "malformed_embedded_dialect",
        "unsupported_embedded_dialect",
        "cross_dialect_resource",
    }:
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema declares an unsupported or ambiguous schema dialect boundary.",
        )
    if kind == "schema_error":
        return ValidationResult(
            name="json_schema",
            status=ValidationStatus.NOT_VERIFIED,
            summary="JSON Schema itself is invalid; payload validity was not proven.",
        )
    return ValidationResult(
        name="json_schema",
        status=ValidationStatus.NOT_VERIFIED,
        summary="Isolated JSON Schema validation did not complete with a recognized result.",
    )
