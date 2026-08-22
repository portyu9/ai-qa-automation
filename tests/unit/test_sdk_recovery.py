from __future__ import annotations

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.sdk_recovery import (
    retry_decision,
    retry_delay_seconds,
    sdk_exception_is_transient,
)


def _state(**updates: object) -> AgentRunState:
    state = AgentRunState(objective="test", workspace="/tmp/target")
    for key, value in updates.items():
        setattr(state, key, value)
    return state


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


def test_retry_is_allowed_only_before_any_observable_or_side_effecting_activity() -> None:
    clean = retry_decision(
        ConnectionError("connection refused"),
        state=_state(),
        retry_limit=2,
        pending_mutation=False,
    )
    assert clean.retry is True
    assert clean.category == "transient_pre_activity"

    assert (
        retry_decision(
            ConnectionError("connection reset"),
            state=_state(iteration=1),
            retry_limit=2,
            pending_mutation=False,
        ).category
        == "message_observed"
    )
    assert (
        retry_decision(
            ConnectionError("connection reset"),
            state=_state(tool_call_count=1),
            retry_limit=2,
            pending_mutation=False,
        ).category
        == "tool_activity"
    )
    assert (
        retry_decision(
            ConnectionError("connection reset"),
            state=_state(files_modified=["tests/test_checkout.py"]),
            retry_limit=2,
            pending_mutation=False,
        ).category
        == "mutation_history"
    )
    assert (
        retry_decision(
            ConnectionError("connection reset"),
            state=_state(),
            retry_limit=2,
            pending_mutation=True,
        ).category
        == "pending_mutation"
    )


def test_retry_budget_and_backoff_are_bounded_and_deterministic() -> None:
    exhausted = retry_decision(
        ConnectionError("connection reset"),
        state=_state(retry_count=2),
        retry_limit=2,
        pending_mutation=False,
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
