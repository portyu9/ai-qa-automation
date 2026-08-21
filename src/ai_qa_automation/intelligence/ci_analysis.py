from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CIFailureSignal:
    category: str
    confidence: float
    summary: str


def analyze_ci_failure(*, exit_code: int, log_tail: str) -> CIFailureSignal:
    """Deterministic first-pass CI triage before model interpretation."""
    text = log_tail.lower()
    if exit_code == 0:
        return CIFailureSignal("PASS", 1.0, "CI command exited successfully.")
    patterns = [
        ("AUTHENTICATION_FAILURE", ("401", "403", "bad credentials", "authentication failed", "permission denied")),
        ("RATE_LIMIT", ("rate limit", "too many requests", "429")),
        ("NETWORK_FAILURE", ("connection refused", "dns", "temporary failure in name resolution", "timed out")),
        ("CONFIGURATION_FAILURE", ("configuration error", "invalid config", "missing environment variable", "not found in path")),
        ("DEPENDENCY_FAILURE", ("could not resolve", "dependency conflict", "no matching distribution", "package not found")),
        ("TEST_FAILURE", ("failed", "assertionerror", "test failures")),
    ]
    for category, needles in patterns:
        if any(needle in text for needle in needles):
            return CIFailureSignal(category, 0.85, f"Observed log markers consistent with {category}.")
    return CIFailureSignal("UNKNOWN", 0.4, "Non-zero CI exit observed without a discriminating known marker.")
