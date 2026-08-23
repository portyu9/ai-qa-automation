from __future__ import annotations

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.sdk_recovery import (
    SDKRetryDecision,
    retry_decision,
    retry_delay_seconds,
    retry_failure_reason,
    sdk_exception_is_transient,
)


def _state(**updates: object) -> AgentRunState:
    state = AgentRunState(objective="test", workspace="/tmp/target")
    for key, value in updates.items():
        setattr(state, key, value)
    return state


def _decision(
    exc: BaseException,
    *,
    state: AgentRunState | None = None,
    retry_limit: int = 2,
    pending_mutation: bool = False,
    provider_request_started: bool = False,
) -> SDKRetryDecision:
    return retry_decision(
        exc,
        state=state or _state(),
        retry_limit=retry_limit,
        pending_mutation=pending_mutation,
        provider_request_started=provider_request_started,
    )


def test_transient_classifier_accepts_transport_rate_limit_and_wrapped_failures() -> None:
    assert sdk_exception_is_transient(ConnectionError("connection reset")) is True
    assert sdk_exception_is_transient(RuntimeError("API Error: 429 rate_limit_error")) is True
    assert sdk_exception_is_transient(RuntimeError("529 overloaded_error")) is True
    assert (
        sdk_exception_is_transient(
            ExceptionGroup("sdk task group", [ConnectionError("connection closed")])
        )
        is True
    )


def test_transient_classifier_rejects_auth_configuration_and_schema_failures() -> None:
    assert sdk_exception_is_transient(RuntimeError("401 invalid API key")) is False
    assert sdk_exception_is_transient(ConnectionError("401 unauthorized")) is False
    assert sdk_exception_is_transient(RuntimeError("permission denied")) is False
    assert sdk_exception_is_transient(RuntimeError("argument list too long")) is False
    assert sdk_exception_is_transient(ValueError("malformed schema")) is False
    assert (
        sdk_exception_is_transient(
            ExceptionGroup(
                "mixed",
                [ConnectionError("connection reset"), RuntimeError("401 unauthorized")],
            )
        )
        is False
    )


def test_retry_is_allowed_only_for_transient_session_start_failure() -> None:
    clean = _decision(ConnectionError("connection refused"))
    assert clean.retry is True
    assert clean.category == "transient_session_start"

    provider_started = _decision(
        ConnectionError("connection reset"),
        provider_request_started=True,
    )
    assert provider_started.retry is False
    assert provider_started.category == "provider_request_started"

    exhausted_after_provider_start = _decision(
        ConnectionError("connection reset"),
        state=_state(retry_count=2),
        provider_request_started=True,
    )
    assert exhausted_after_provider_start.category == "provider_request_started"

    assert (
        _decision(ConnectionError("connection reset"), state=_state(iteration=1)).category
        == "message_observed"
    )
    assert (
        _decision(ConnectionError("connection reset"), state=_state(tool_call_count=1)).category
        == "tool_activity"
    )
    assert (
        _decision(
            ConnectionError("connection reset"),
            state=_state(files_modified=["tests/test_checkout.py"]),
        ).category
        == "mutation_history"
    )
    assert (
        _decision(ConnectionError("connection reset"), pending_mutation=True).category
        == "pending_mutation"
    )


def test_non_retryable_semantics_dominate_provider_activity_and_transport_type() -> None:
    decision = _decision(
        ConnectionError("401 unauthorized"),
        provider_request_started=True,
    )

    assert decision.retry is False
    assert decision.category == "non_transient"


def test_retry_budget_and_backoff_are_bounded_and_deterministic() -> None:
    exhausted = _decision(
        ConnectionError("connection reset"),
        state=_state(retry_count=2),
    )
    assert exhausted.retry is False
    assert exhausted.category == "retry_budget"

    assert retry_delay_seconds(1, base_seconds=1.0, max_seconds=4.0) == 1.0
    assert retry_delay_seconds(2, base_seconds=1.0, max_seconds=4.0) == 2.0
    assert retry_delay_seconds(3, base_seconds=1.0, max_seconds=4.0) == 4.0
    assert retry_delay_seconds(8, base_seconds=1.0, max_seconds=4.0) == 4.0

    with pytest.raises(ValueError):
        retry_delay_seconds(0, base_seconds=1.0, max_seconds=4.0)
    with pytest.raises(ValueError):
        retry_delay_seconds(1, base_seconds=0.0, max_seconds=4.0)
    with pytest.raises(ValueError):
        retry_delay_seconds(1, base_seconds=2.0, max_seconds=1.0)


def test_retry_failure_reason_preserves_replay_denial_truth() -> None:
    provider_started = _decision(
        ConnectionError("connection reset"),
        provider_request_started=True,
    )
    provider_reason = retry_failure_reason(provider_started, ConnectionError("connection reset"))
    assert provider_reason is not None
    assert "provider query submission already started" in provider_reason

    exhausted = _decision(ConnectionError("connection reset"), retry_limit=0)
    exhausted_reason = retry_failure_reason(exhausted, ConnectionError("connection reset"))
    assert exhausted_reason is not None
    assert "retry budget was exhausted" in exhausted_reason

    clean = _decision(ConnectionError("connection reset"))
    assert retry_failure_reason(clean, ConnectionError("connection reset")) is None
    non_transient = _decision(RuntimeError("401 unauthorized"))
    assert retry_failure_reason(non_transient, RuntimeError("401 unauthorized")) is None
