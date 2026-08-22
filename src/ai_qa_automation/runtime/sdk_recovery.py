from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..models import AgentRunState

_RETRYABLE_TYPE_NAMES = {
    "APIConnectionError",
    "APITimeoutError",
    "InternalServerError",
    "RateLimitError",
}
_RETRYABLE_MARKERS = (
    "429",
    "529",
    "rate limit",
    "rate_limit",
    "overloaded",
    "temporarily unavailable",
    "temporarily limiting requests",
    "connection reset",
    "connection refused",
    "connection closed",
    "connection aborted",
    "broken pipe",
    " epipe",
)
_NON_RETRYABLE_MARKERS = (
    "401",
    "403",
    "authentication",
    "unauthorized",
    "invalid api key",
    "invalid_api_key",
    "permission denied",
    "argument list too long",
    "not found",
    "no such file",
    "malformed",
    "schema",
)


@dataclass(frozen=True, slots=True)
class SDKRetryDecision:
    retry: bool
    category: str
    reason: str


def _exception_leaves(exc: BaseException) -> Iterable[BaseException]:
    nested = getattr(exc, "exceptions", None)
    if isinstance(nested, tuple | list):
        for item in nested:
            if isinstance(item, BaseException):
                yield from _exception_leaves(item)
        return
    yield exc


def _leaf_is_transient(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionError):
        return True
    if isinstance(exc, TimeoutError):
        return True

    type_name = type(exc).__name__
    text = f"{type_name}: {exc}".casefold()
    if any(marker in text for marker in _NON_RETRYABLE_MARKERS):
        return False
    if type_name in _RETRYABLE_TYPE_NAMES:
        return True
    return any(marker in text for marker in _RETRYABLE_MARKERS)


def sdk_exception_is_transient(exc: BaseException) -> bool:
    """Classify only explicitly transient SDK/provider failure shapes as retryable.

    The classifier intentionally avoids private Agent SDK exception imports. It
    handles built-in transport failures, documented Anthropic API error names,
    and ExceptionGroup-style wrappers while rejecting auth/config/schema/local
    executable failures even when their outer wrapper is generic.
    """

    leaves = list(_exception_leaves(exc))
    return bool(leaves) and all(_leaf_is_transient(item) for item in leaves)


def retry_decision(
    exc: BaseException,
    *,
    state: AgentRunState,
    retry_limit: int,
    pending_mutation: bool,
) -> SDKRetryDecision:
    if state.retry_count >= retry_limit:
        return SDKRetryDecision(False, "retry_budget", "bounded SDK retry budget exhausted")
    if not sdk_exception_is_transient(exc):
        return SDKRetryDecision(False, "non_transient", "SDK failure is not classified as transient")
    if state.iteration != 0:
        return SDKRetryDecision(
            False,
            "message_observed",
            "SDK response activity already occurred; replay could duplicate model/provider work",
        )
    if state.tool_call_count != 0:
        return SDKRetryDecision(
            False,
            "tool_activity",
            "controlled tool activity already occurred; replay could duplicate side effects",
        )
    if state.files_modified:
        return SDKRetryDecision(
            False,
            "mutation_history",
            "workspace mutation history exists; replay is not side-effect safe",
        )
    if pending_mutation:
        return SDKRetryDecision(
            False,
            "pending_mutation",
            "a mutation transaction is pending; replay is forbidden",
        )
    return SDKRetryDecision(
        True,
        "transient_pre_activity",
        "transient SDK failure occurred before any observable agent/tool activity",
    )


def retry_delay_seconds(
    retry_number: int,
    *,
    base_seconds: float,
    max_seconds: float,
) -> float:
    """Deterministic bounded exponential backoff; retry_number is 1-based."""
    if retry_number < 1:
        raise ValueError("retry_number must be >= 1")
    return min(float(max_seconds), float(base_seconds) * (2 ** (retry_number - 1)))
