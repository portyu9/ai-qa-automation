from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from ..redaction import redact_text


def k6_gate_payload(tool_input: Mapping[str, Any]) -> dict[str, str | float]:
    """Normalize and validate the complete six-field k6 validation subject."""
    text_values: dict[str, str] = {}
    for name in ("script", "target_url", "environment"):
        value = tool_input.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        text_values[name] = value

    thresholds: dict[str, float] = {}
    for name in ("max_p95_ms", "max_error_rate", "min_request_rate"):
        raw = tool_input.get(name)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"{name} must be numeric")
        try:
            value = float(raw)
        except OverflowError as exc:
            raise ValueError(f"{name} must be finite") from exc
        if not math.isfinite(value):
            raise ValueError(f"{name} must be finite")
        if value < 0:
            raise ValueError(f"{name} must be non-negative")
        thresholds[name] = value
    if thresholds["max_error_rate"] > 1:
        raise ValueError("max_error_rate must be between 0 and 1")

    return {**text_values, **thresholds}


def k6_persisted_subject(
    payload: Mapping[str, str | float],
) -> dict[str, str | float]:
    """Render the k6 subject for durable details without leaking URL secrets."""
    return {
        "script": str(payload["script"]),
        "target_url": redact_text(str(payload["target_url"])),
        "environment": str(payload["environment"]),
        "max_p95_ms": float(payload["max_p95_ms"]),
        "max_error_rate": float(payload["max_error_rate"]),
        "min_request_rate": float(payload["min_request_rate"]),
    }
