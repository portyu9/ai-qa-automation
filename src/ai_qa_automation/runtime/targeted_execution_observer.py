from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any

from pydantic import Field, field_validator, model_validator

from ..models import FrozenModel

TRUSTED_TARGETED_EXECUTION_AUTHORITY = "trusted_out_of_process_observer_v1"
TARGETED_EXECUTION_SCHEMA = "ai-qa-targeted-execution-observer/v1"

_MAX_RUN_ID_BYTES = 256
_MAX_OBSERVER_BACKEND_BYTES = 128
_MAX_PYTEST_ARGS = 64
_MAX_PYTEST_ARG_BYTES = 4096
_MAX_PYTEST_ARGS_TOTAL_BYTES = 64_000
_MAX_TARGET_PATH_BYTES = 4096
_MAX_PASSED_PATHS = 4
_SAFE_RUN_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
)


def canonical_targeted_execution_id(payload: dict[str, Any]) -> str:
    """Bind one observer result to its exact canonical structured subject."""

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def normalize_targeted_path(value: object) -> str | None:
    """Return one canonical repository-relative POSIX path or None."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    if len(value.encode("utf-8")) > _MAX_TARGET_PATH_BYTES:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if path.as_posix() != value:
        return None
    return value


def _pytest_args_select_mutation(pytest_args: tuple[str, ...], mutation_path: str) -> bool:
    """Require at least one canonical selector to bind the exact mutation path."""

    skip_next = False
    for raw in pytest_args:
        if skip_next:
            skip_next = False
            continue
        if raw in {"-k", "-m", "--maxfail", "--tb"}:
            skip_next = True
            continue
        if raw.startswith("-"):
            continue
        selector = raw.split("::", 1)[0]
        if normalize_targeted_path(selector) == mutation_path:
            return True
    return False


class TargetedExecutionObservation(FrozenModel):
    """Authority-bearing targeted-test observation emitted only by a trusted observer."""

    schema_version: str = TARGETED_EXECUTION_SCHEMA
    authority: str = TRUSTED_TARGETED_EXECUTION_AUTHORITY
    execution_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    run_id: str = Field(min_length=1, max_length=_MAX_RUN_ID_BYTES)
    change_revision: int = Field(ge=1)
    mutation_path: str = Field(min_length=1, max_length=_MAX_TARGET_PATH_BYTES)
    pytest_args: tuple[str, ...] = Field(max_length=_MAX_PYTEST_ARGS)
    observer_backend: str = Field(
        min_length=1,
        max_length=_MAX_OBSERVER_BACKEND_BYTES,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    observer_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    git_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_subject_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    report_complete: bool
    child_exit_code: int
    pytest_returncode: int
    call_report_count: int = Field(ge=0)
    passed_call_count: int = Field(ge=0)
    skipped_call_count: int = Field(ge=0)
    xfail_call_count: int = Field(ge=0)
    failed_call_count: int = Field(ge=0)
    passed_paths: tuple[str, ...] = Field(max_length=_MAX_PASSED_PATHS)
    report_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("run_id")
    @classmethod
    def bounded_run_id(cls, value: str) -> str:
        if (
            not value.isascii()
            or any(char not in _SAFE_RUN_ID_CHARS for char in value)
            or len(value.encode("utf-8")) > _MAX_RUN_ID_BYTES
        ):
            raise ValueError("targeted observer run_id is invalid")
        return value

    @field_validator("mutation_path")
    @classmethod
    def canonical_mutation_path(cls, value: str) -> str:
        normalized = normalize_targeted_path(value)
        if normalized is None:
            raise ValueError("targeted observer mutation path is not canonical")
        return normalized

    @field_validator("pytest_args")
    @classmethod
    def bounded_pytest_args(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        total = 0
        for value in values:
            if not value or "\x00" in value:
                raise ValueError("targeted observer pytest args contain an invalid value")
            size = len(value.encode("utf-8"))
            if size > _MAX_PYTEST_ARG_BYTES:
                raise ValueError("targeted observer pytest arg exceeds its byte bound")
            total += size
        if total > _MAX_PYTEST_ARGS_TOTAL_BYTES:
            raise ValueError("targeted observer pytest args exceed their aggregate byte bound")
        return values

    @field_validator("passed_paths")
    @classmethod
    def canonical_passed_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            path = normalize_targeted_path(value)
            if path is None:
                raise ValueError("targeted observer passed path is not canonical")
            normalized.append(path)
        if len(set(normalized)) != len(normalized):
            raise ValueError("targeted observer passed paths must be unique")
        return tuple(normalized)

    @model_validator(mode="after")
    def validate_observation_identity(self) -> TargetedExecutionObservation:
        if self.schema_version != TARGETED_EXECUTION_SCHEMA:
            raise ValueError("unsupported targeted execution observer schema")
        if self.authority != TRUSTED_TARGETED_EXECUTION_AUTHORITY:
            raise ValueError("unsupported targeted execution observer authority")
        counted = (
            self.passed_call_count
            + self.skipped_call_count
            + self.xfail_call_count
            + self.failed_call_count
        )
        if counted != self.call_report_count:
            raise ValueError("targeted observer call-phase counts are inconsistent")
        if self.passed_call_count < len(self.passed_paths):
            raise ValueError("targeted observer passed paths exceed passing call count")
        if self.passed_call_count == 0 and self.passed_paths:
            raise ValueError("targeted observer cannot record passed paths without a passing call")
        payload = self.model_dump(mode="json", exclude={"execution_id"})
        if self.execution_id != canonical_targeted_execution_id(payload):
            raise ValueError("targeted observer execution_id does not match canonical observation")
        return self


def build_targeted_execution_observation(**values: Any) -> TargetedExecutionObservation:
    """Build one canonical observation and derive its execution identity."""

    payload = dict(values)
    payload.setdefault("schema_version", TARGETED_EXECUTION_SCHEMA)
    payload.setdefault("authority", TRUSTED_TARGETED_EXECUTION_AUTHORITY)
    provisional = {**payload, "execution_id": "sha256:" + "0" * 64}
    parsed = TargetedExecutionObservation.model_construct(**provisional)
    canonical_payload = parsed.model_dump(mode="json", exclude={"execution_id"})
    return TargetedExecutionObservation.model_validate(
        {
            **payload,
            "execution_id": canonical_targeted_execution_id(canonical_payload),
        }
    )


def verified_targeted_execution_observation(
    payload: object,
    *,
    expected_run_id: str,
    expected_revision: int,
    expected_mutation_path: str,
    expected_pytest_args: tuple[str, ...],
) -> TargetedExecutionObservation | None:
    """Accept only one exact, positive observer result for the canonical runtime subject."""

    expected_path = normalize_targeted_path(expected_mutation_path)
    if (
        not isinstance(payload, dict)
        or not expected_run_id
        or expected_revision < 1
        or expected_path is None
    ):
        return None
    try:
        observation = TargetedExecutionObservation.model_validate(payload)
    except ValueError:
        return None
    if observation.run_id != expected_run_id or observation.change_revision != expected_revision:
        return None
    if observation.mutation_path != expected_path:
        return None
    if observation.pytest_args != expected_pytest_args:
        return None
    if not _pytest_args_select_mutation(observation.pytest_args, expected_path):
        return None
    if not observation.report_complete:
        return None
    if observation.child_exit_code != 0 or observation.pytest_returncode != 0:
        return None
    if observation.failed_call_count != 0 or observation.passed_call_count < 1:
        return None
    if expected_path not in observation.passed_paths:
        return None
    return observation
