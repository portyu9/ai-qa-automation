from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import Field, StrictBool, StrictInt, StrictStr, field_validator, model_validator

from ..models import FrozenModel

TRUSTED_REGRESSION_EXECUTION_AUTHORITY = "trusted_out_of_process_observer_v1"
REGRESSION_EXECUTION_SCHEMA = "ai-qa-regression-execution-observer/v1"

_MAX_RUN_ID_BYTES = 256
_MAX_OBSERVER_BACKEND_BYTES = 128
_MAX_PYTEST_ARGS = 64
_MAX_PYTEST_ARG_BYTES = 4096
_MAX_PYTEST_ARGS_TOTAL_BYTES = 64_000
_MAX_OBSERVED_ITEMS = 10_000
_SAFE_RUN_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")


def canonical_regression_execution_id(payload: dict[str, Any]) -> str:
    """Bind one independent regression observation to its exact structured subject."""

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


class RegressionExecutionObservation(FrozenModel):
    """Schema for full-regression semantics only a separately trusted observer may author."""

    schema_version: StrictStr = REGRESSION_EXECUTION_SCHEMA
    authority: StrictStr = TRUSTED_REGRESSION_EXECUTION_AUTHORITY
    execution_id: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    run_id: StrictStr = Field(min_length=1, max_length=_MAX_RUN_ID_BYTES)
    change_revision: StrictInt = Field(ge=1)
    pytest_args: tuple[StrictStr, ...] = Field(max_length=_MAX_PYTEST_ARGS)
    observer_backend: StrictStr = Field(
        min_length=1,
        max_length=_MAX_OBSERVER_BACKEND_BYTES,
        pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$",
    )
    observer_identity: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    git_sha: StrictStr = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    source_fingerprint: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_subject_digest: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    regression_suite_id: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    node_count: StrictInt = Field(ge=1, le=_MAX_OBSERVED_ITEMS)
    nodeids_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    collection_complete: StrictBool
    execution_complete: StrictBool
    report_complete: StrictBool
    child_exit_code: StrictInt = Field(ge=-255, le=255)
    pytest_returncode: StrictInt = Field(ge=0, le=255)
    observed_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    passed_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    skipped_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    xfail_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    xpass_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    failed_item_count: StrictInt = Field(ge=0, le=_MAX_OBSERVED_ITEMS)
    observed_nodeids_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    report_sha256: StrictStr = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("run_id")
    @classmethod
    def bounded_run_id(cls, value: str) -> str:
        if (
            not value.isascii()
            or any(char not in _SAFE_RUN_ID_CHARS for char in value)
            or len(value.encode("utf-8")) > _MAX_RUN_ID_BYTES
        ):
            raise ValueError("regression observer run_id is invalid")
        return value

    @field_validator("pytest_args")
    @classmethod
    def bounded_pytest_args(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        total = 0
        for value in values:
            if not value or "\x00" in value:
                raise ValueError("regression observer pytest args contain an invalid value")
            size = len(value.encode("utf-8"))
            if size > _MAX_PYTEST_ARG_BYTES:
                raise ValueError("regression observer pytest arg exceeds its byte bound")
            total += size
        if total > _MAX_PYTEST_ARGS_TOTAL_BYTES:
            raise ValueError("regression observer pytest args exceed their aggregate byte bound")
        return values

    @model_validator(mode="after")
    def validate_observation_identity(self) -> RegressionExecutionObservation:
        if self.schema_version != REGRESSION_EXECUTION_SCHEMA:
            raise ValueError("unsupported regression execution observer schema")
        if self.authority != TRUSTED_REGRESSION_EXECUTION_AUTHORITY:
            raise ValueError("unsupported regression execution observer authority")
        counted = (
            self.passed_item_count
            + self.skipped_item_count
            + self.xfail_item_count
            + self.xpass_item_count
            + self.failed_item_count
        )
        if counted != self.observed_item_count:
            raise ValueError("regression observer item counts are inconsistent")
        payload = self.model_dump(mode="json", exclude={"execution_id"})
        if self.execution_id != canonical_regression_execution_id(payload):
            raise ValueError(
                "regression observer execution_id does not match canonical observation"
            )
        return self


def build_regression_execution_observation(**values: Any) -> RegressionExecutionObservation:
    """Build one canonical regression observation and derive its execution identity."""

    payload = dict(values)
    payload.setdefault("schema_version", REGRESSION_EXECUTION_SCHEMA)
    payload.setdefault("authority", TRUSTED_REGRESSION_EXECUTION_AUTHORITY)
    provisional = {**payload, "execution_id": "sha256:" + "0" * 64}
    parsed = RegressionExecutionObservation.model_construct(**provisional)
    canonical_payload = parsed.model_dump(mode="json", exclude={"execution_id"})
    return RegressionExecutionObservation.model_validate(
        {
            **payload,
            "execution_id": canonical_regression_execution_id(canonical_payload),
        }
    )


def verified_regression_execution_observation(
    payload: object,
    *,
    expected_run_id: str,
    expected_revision: int,
    expected_pytest_args: tuple[str, ...],
    expected_observer_backend: str,
    expected_observer_identity: str,
    expected_git_sha: str,
    expected_source_fingerprint: str,
    expected_execution_subject_digest: str,
    expected_regression_suite_id: str,
    expected_node_count: int,
    expected_nodeids_sha256: str,
) -> RegressionExecutionObservation | None:
    """Accept only one exact positive result matching controller-owned regression authority."""

    if (
        not isinstance(payload, dict)
        or not expected_run_id
        or expected_revision < 1
        or not expected_observer_backend
        or not expected_observer_identity
        or not expected_git_sha
        or not expected_source_fingerprint
        or not expected_execution_subject_digest
        or not expected_regression_suite_id
        or expected_node_count < 1
        or not expected_nodeids_sha256
    ):
        return None
    try:
        observation = RegressionExecutionObservation.model_validate(payload)
    except ValueError:
        return None
    if observation.run_id != expected_run_id or observation.change_revision != expected_revision:
        return None
    if observation.pytest_args != expected_pytest_args:
        return None
    if (
        observation.observer_backend != expected_observer_backend
        or observation.observer_identity != expected_observer_identity
    ):
        return None
    if (
        observation.git_sha != expected_git_sha
        or observation.source_fingerprint != expected_source_fingerprint
        or observation.execution_subject_digest != expected_execution_subject_digest
    ):
        return None
    if (
        observation.regression_suite_id != expected_regression_suite_id
        or observation.node_count != expected_node_count
        or observation.nodeids_sha256 != expected_nodeids_sha256
    ):
        return None
    if not observation.collection_complete or not observation.execution_complete:
        return None
    if not observation.report_complete:
        return None
    if observation.child_exit_code != 0 or observation.pytest_returncode != 0:
        return None
    if observation.failed_item_count != 0 or observation.passed_item_count < 1:
        return None
    if observation.observed_item_count != expected_node_count:
        return None
    if observation.observed_nodeids_sha256 != expected_nodeids_sha256:
        return None
    return observation
