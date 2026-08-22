from __future__ import annotations

import math

import pytest

from ai_qa_automation.intelligence.performance import PerformanceAssessor
from ai_qa_automation.models import PerformanceMetrics


def _metrics() -> PerformanceMetrics:
    return PerformanceMetrics(
        p50_ms=100,
        p90_ms=200,
        p95_ms=250,
        p99_ms=400,
        request_rate=50,
        error_rate=0.01,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_p95_ms", math.nan),
        ("max_p95_ms", math.inf),
        ("max_error_rate", math.nan),
        ("min_request_rate", -1.0),
        ("max_error_rate", 1.01),
    ],
)
def test_invalid_performance_thresholds_fail_closed(field: str, value: float) -> None:
    kwargs = {
        "max_p95_ms": 500.0,
        "max_error_rate": 0.05,
        "min_request_rate": 1.0,
    }
    kwargs[field] = value

    with pytest.raises(ValueError):
        PerformanceAssessor().assess(_metrics(), **kwargs)
