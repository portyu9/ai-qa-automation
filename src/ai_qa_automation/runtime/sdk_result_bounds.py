from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

MAX_SDK_RESULT_UTF8_BYTES = 256_000
MAX_SDK_SUBTYPE_UTF8_BYTES = 256
MAX_SDK_USAGE_KEYS = 64
MAX_SDK_TOKEN_COUNT = 1_000_000_000


class SDKResultBoundsError(ValueError):
    """An Agent SDK terminal result violated the deterministic ingestion contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class BoundedSDKResult:
    result: str
    subtype: str
    total_cost_usd: float
    token_usage: int
    budget_exceeded: bool


def _bounded_text(value: Any, *, label: str, max_utf8_bytes: int, allow_none: bool) -> str:
    if value is None and allow_none:
        return ""
    if type(value) is not str:
        raise SDKResultBoundsError(
            f"{label}_type",
            f"Agent SDK {label} must be a string",
        )
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise SDKResultBoundsError(
            f"{label}_unicode",
            f"Agent SDK {label} contains invalid Unicode",
        ) from exc
    if size > max_utf8_bytes:
        raise SDKResultBoundsError(
            f"{label}_bytes",
            f"Agent SDK {label} exceeds the deterministic UTF-8 size bound",
        )
    return value


def _bounded_token_count(value: Any, *, label: str) -> int:
    if type(value) is not int:
        raise SDKResultBoundsError(
            "usage_token_type",
            f"Agent SDK {label} must be a non-negative integer",
        )
    if value < 0:
        raise SDKResultBoundsError(
            "usage_token_negative",
            f"Agent SDK {label} must be non-negative",
        )
    if value > MAX_SDK_TOKEN_COUNT:
        raise SDKResultBoundsError(
            "usage_token_bound",
            f"Agent SDK {label} exceeds the deterministic token-count bound",
        )
    return value


def _bounded_cost(value: Any) -> float:
    if value is None:
        return 0.0
    if type(value) not in (int, float):
        raise SDKResultBoundsError(
            "cost_type",
            "Agent SDK total_cost_usd must be a finite non-negative number",
        )
    try:
        cost = float(value)
    except (OverflowError, ValueError) as exc:
        raise SDKResultBoundsError(
            "cost_value",
            "Agent SDK total_cost_usd cannot be represented safely",
        ) from exc
    if not math.isfinite(cost):
        raise SDKResultBoundsError(
            "cost_non_finite",
            "Agent SDK total_cost_usd must be finite",
        )
    if cost < 0:
        raise SDKResultBoundsError(
            "cost_negative",
            "Agent SDK total_cost_usd must be non-negative",
        )
    return cost


def validate_sdk_result_message(message: Any, *, max_cost_usd: float) -> BoundedSDKResult:
    """Validate one terminal SDK result before retaining or trusting any of its fields."""

    result = _bounded_text(
        getattr(message, "result", None),
        label="result",
        max_utf8_bytes=MAX_SDK_RESULT_UTF8_BYTES,
        allow_none=True,
    )
    subtype = _bounded_text(
        getattr(message, "subtype", None),
        label="subtype",
        max_utf8_bytes=MAX_SDK_SUBTYPE_UTF8_BYTES,
        allow_none=False,
    )
    cost = _bounded_cost(getattr(message, "total_cost_usd", None))

    usage = getattr(message, "usage", None)
    if usage is None:
        usage = {}
    if type(usage) is not dict:
        raise SDKResultBoundsError(
            "usage_type",
            "Agent SDK usage must be a JSON-like object",
        )
    if len(usage) > MAX_SDK_USAGE_KEYS:
        raise SDKResultBoundsError(
            "usage_keys",
            "Agent SDK usage exceeds the deterministic key-count bound",
        )

    input_tokens = _bounded_token_count(usage.get("input_tokens", 0), label="input_tokens")
    output_tokens = _bounded_token_count(
        usage.get("output_tokens", 0), label="output_tokens"
    )
    token_usage = input_tokens + output_tokens
    if token_usage > MAX_SDK_TOKEN_COUNT:
        raise SDKResultBoundsError(
            "usage_total_bound",
            "Agent SDK total token usage exceeds the deterministic bound",
        )

    return BoundedSDKResult(
        result=result,
        subtype=subtype,
        total_cost_usd=cost,
        token_usage=token_usage,
        budget_exceeded=cost > max_cost_usd,
    )
