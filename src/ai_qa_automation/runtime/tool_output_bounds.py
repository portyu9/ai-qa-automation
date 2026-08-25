from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast

from ..redaction import sanitize
from .tool_input_bounds import ToolInputBoundsError, validate_json_value

MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES = 256_000
MAX_EXTERNAL_TOOL_OUTPUT_NODES = 20_000
MAX_EXTERNAL_TOOL_OUTPUT_DEPTH = 24
MAX_EXTERNAL_TOOL_OUTPUT_CONTAINER_ITEMS = 10_000
MAX_EXTERNAL_TOOL_OUTPUT_CANONICAL_BYTES = 2_000_000
MAX_EXTERNAL_TOOL_OUTPUT_EXCERPT_CHARS = 12_000
MAX_EXTERNAL_FAILURE_MESSAGE_UTF8_BYTES = 16_000


class ToolOutputBoundsError(ValueError):
    """An external tool result exceeded the deterministic posttool boundary."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CanonicalOutputSummary:
    response_hash: str
    excerpt: str
    excerpt_hash: str
    truncated: bool
    canonical_bytes: int


def _validate_json_output(value: Any, *, label: str) -> None:
    if not isinstance(value, (dict, list)):
        raise ToolOutputBoundsError(
            "root_type",
            f"{label} must be a JSON object or array",
        )
    try:
        validate_json_value(
            value,
            max_utf8_bytes=MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES,
            max_nodes=MAX_EXTERNAL_TOOL_OUTPUT_NODES,
            max_depth=MAX_EXTERNAL_TOOL_OUTPUT_DEPTH,
            max_container_items=MAX_EXTERNAL_TOOL_OUTPUT_CONTAINER_ITEMS,
            label=label,
        )
    except ToolInputBoundsError as exc:
        raise ToolOutputBoundsError(exc.code, str(exc)) from exc
    if isinstance(value, dict) and "is_error" in value and not isinstance(value["is_error"], bool):
        raise ToolOutputBoundsError(
            "error_flag_type",
            f"{label} contains a non-boolean is_error flag",
        )


def validate_external_tool_output(value: Any) -> None:
    """Bound an external provider result before recursive sanitization or serialization."""

    _validate_json_output(value, label="external tool output")


def validate_external_failure_message(value: Any) -> str:
    """Accept only a bounded UTF-8 provider failure string without arbitrary coercion."""

    if not isinstance(value, str):
        raise ToolOutputBoundsError(
            "failure_message_type",
            "external tool failure message must be a string",
        )
    try:
        validate_json_value(
            value,
            max_utf8_bytes=MAX_EXTERNAL_FAILURE_MESSAGE_UTF8_BYTES,
            max_nodes=1,
            max_depth=0,
            max_container_items=1,
            label="external tool failure message",
        )
    except ToolInputBoundsError as exc:
        raise ToolOutputBoundsError(exc.code, str(exc)) from exc
    return value


def _canonical_summary(value: dict[str, Any] | list[Any]) -> CanonicalOutputSummary:
    digest = hashlib.sha256()
    excerpt_digest = hashlib.sha256()
    excerpt_parts: list[str] = []
    excerpt_remaining = MAX_EXTERNAL_TOOL_OUTPUT_EXCERPT_CHARS
    canonical_bytes = 0
    canonical_chars = 0

    encoder = json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False)
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        canonical_bytes += len(encoded)
        if canonical_bytes > MAX_EXTERNAL_TOOL_OUTPUT_CANONICAL_BYTES:
            raise ToolOutputBoundsError(
                "canonical_bytes",
                "sanitized external tool output exceeds the deterministic canonical JSON bound",
            )
        digest.update(encoded)
        canonical_chars += len(chunk)
        if excerpt_remaining > 0:
            fragment = chunk[:excerpt_remaining]
            excerpt_parts.append(fragment)
            excerpt_digest.update(fragment.encode("utf-8"))
            excerpt_remaining -= len(fragment)

    excerpt = "".join(excerpt_parts)
    return CanonicalOutputSummary(
        response_hash=f"sha256:{digest.hexdigest()}",
        excerpt=excerpt,
        excerpt_hash=f"sha256:{excerpt_digest.hexdigest()}",
        truncated=canonical_chars > len(excerpt),
        canonical_bytes=canonical_bytes,
    )


def prepare_external_tool_output(
    value: Any,
) -> tuple[dict[str, Any] | list[Any], CanonicalOutputSummary]:
    """Validate, sanitize, revalidate, and summarize provider output without full rendering."""

    validate_external_tool_output(value)
    safe = sanitize(value)
    _validate_json_output(safe, label="sanitized external tool output")
    typed_safe = cast(dict[str, Any] | list[Any], safe)
    return typed_safe, _canonical_summary(typed_safe)
