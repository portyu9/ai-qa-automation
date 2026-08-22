from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from ai_qa_automation.models import AgentRunState, PerformanceMetrics, RegressionCandidate


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_agent_state_rejects_non_finite_runtime_numbers(value: float) -> None:
    with pytest.raises(ValidationError):
        AgentRunState(objective="finite", workspace=".", cost=value)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_performance_metrics_reject_non_finite_measurements(value: float) -> None:
    with pytest.raises(ValidationError):
        PerformanceMetrics(
            p50_ms=1.0,
            p90_ms=2.0,
            p95_ms=value,
            p99_ms=4.0,
            request_rate=5.0,
            error_rate=0.0,
        )


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_regression_candidate_rejects_non_finite_risk_inputs(value: float) -> None:
    with pytest.raises(ValidationError):
        RegressionCandidate(test_id="x", business_criticality=value)
