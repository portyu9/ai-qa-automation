from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CIFailureSignal:
    category: str
    confidence: float
    summary: str


def _mentions_http_status(text: str, code: int) -> bool:
    """Recognize protocol-shaped status text without matching arbitrary numeric IDs."""
    return bool(
        re.search(
            rf"\b(?:http(?:\s+status)?|status(?:\s+code)?|response\s+status(?:\s+code)?)"
            rf"\s*[:=]?\s*{code}\b",
            text,
        )
    )


def analyze_ci_failure(*, exit_code: int, log_tail: str) -> CIFailureSignal:
    """Deterministic first-pass CI triage before model interpretation."""
    text = log_tail.lower()
    if exit_code == 0:
        return CIFailureSignal("PASS", 1.0, "CI command exited successfully.")

    if any(
        token in text
        for token in ("bad credentials", "authentication failed", "unauthorized", "forbidden")
    ) or any(_mentions_http_status(text, code) for code in (401, 403)):
        return CIFailureSignal(
            "AUTHENTICATION_FAILURE",
            0.85,
            "Observed authentication/authorization markers in CI output.",
        )
    if "rate limit" in text or "too many requests" in text or _mentions_http_status(text, 429):
        return CIFailureSignal("RATE_LIMIT", 0.85, "Observed rate-limit markers in CI output.")

    patterns = [
        (
            "NETWORK_FAILURE",
            ("connection refused", "dns", "temporary failure in name resolution", "timed out"),
        ),
        (
            "CONFIGURATION_FAILURE",
            (
                "configuration error",
                "invalid config",
                "missing environment variable",
                "not found in path",
            ),
        ),
        (
            "DEPENDENCY_FAILURE",
            (
                "could not resolve",
                "dependency conflict",
                "no matching distribution",
                "package not found",
            ),
        ),
        ("TEST_FAILURE", ("failed", "assertionerror", "test failures")),
    ]
    for category, needles in patterns:
        if any(needle in text for needle in needles):
            return CIFailureSignal(
                category, 0.85, f"Observed log markers consistent with {category}."
            )
    return CIFailureSignal(
        "UNKNOWN",
        0.4,
        "Non-zero CI exit observed without a discriminating known marker.",
    )
