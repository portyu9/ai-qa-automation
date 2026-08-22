from __future__ import annotations

import json

import pytest

from ai_qa_automation.integrations.mcp_health import normalize_mcp_failure
from ai_qa_automation.models import MCPStatus


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"status_code": 401}, MCPStatus.UNAUTHORIZED),
        ({"status_code": 403}, MCPStatus.UNAUTHORIZED),
        ({"error": PermissionError("denied")}, MCPStatus.UNAUTHORIZED),
        ({"message": "remote returned forbidden"}, MCPStatus.UNAUTHORIZED),
        ({"status_code": 429}, MCPStatus.RATE_LIMITED),
        ({"message": "rate limit exceeded"}, MCPStatus.RATE_LIMITED),
        ({"status_code": 503}, MCPStatus.UNAVAILABLE),
        ({"error": TimeoutError("late")}, MCPStatus.UNAVAILABLE),
        ({"error": ConnectionError("reset")}, MCPStatus.UNAVAILABLE),
        ({"message": "connection refused"}, MCPStatus.UNAVAILABLE),
        ({"payload": "not-structured"}, MCPStatus.INVALID_RESPONSE),
        ({"payload": 42}, MCPStatus.INVALID_RESPONSE),
        ({"payload": {"error": "generic"}}, MCPStatus.FAILED),
        ({"payload": ["generic"]}, MCPStatus.FAILED),
        ({}, MCPStatus.FAILED),
    ],
)
def test_mcp_failure_normalization_matrix(kwargs: dict[str, object], expected: MCPStatus) -> None:
    assert normalize_mcp_failure(**kwargs) is expected


def test_decode_failures_are_invalid_response() -> None:
    json_error = json.JSONDecodeError("bad", "{", 0)
    unicode_error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")

    assert normalize_mcp_failure(error=json_error) is MCPStatus.INVALID_RESPONSE
    assert normalize_mcp_failure(error=unicode_error) is MCPStatus.INVALID_RESPONSE
    assert normalize_mcp_failure(error=TypeError("shape")) is MCPStatus.INVALID_RESPONSE


def test_security_relevant_status_precedence_is_deterministic() -> None:
    # Authentication/authorization failures dominate ambiguous text; a response that
    # says both "403" and "rate limit" must not be softened into a retryable status.
    assert (
        normalize_mcp_failure(status_code=403, message="403 rate limit")
        is MCPStatus.UNAUTHORIZED
    )

    # Explicit rate limiting dominates a malformed-body side effect so callers can
    # apply the correct bounded retry/backoff behavior without inventing evidence.
    assert (
        normalize_mcp_failure(status_code=429, error=TypeError("malformed"))
        is MCPStatus.RATE_LIMITED
    )
