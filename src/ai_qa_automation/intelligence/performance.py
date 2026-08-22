from __future__ import annotations

import math

from ..models import PerformanceAssessment, PerformanceMetrics, ValidationStatus


class PerformanceAssessor:
    def assess(
        self,
        metrics: PerformanceMetrics,
        *,
        max_p95_ms: float,
        max_error_rate: float,
        min_request_rate: float = 0,
    ) -> PerformanceAssessment:
        thresholds = {
            "max_p95_ms": max_p95_ms,
            "max_error_rate": max_error_rate,
            "min_request_rate": min_request_rate,
        }
        for name, value in thresholds.items():
            if not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
            if value < 0:
                raise ValueError(f"{name} must be non-negative")
        if max_error_rate > 1:
            raise ValueError("max_error_rate must be between 0 and 1")

        observed = {
            "p50_ms": metrics.p50_ms,
            "p90_ms": metrics.p90_ms,
            "p95_ms": metrics.p95_ms,
            "p99_ms": metrics.p99_ms,
            "request_rate": metrics.request_rate,
            "error_rate": metrics.error_rate,
        }
        for name, value in observed.items():
            if not math.isfinite(value):
                raise ValueError(f"observed {name} must be finite")

        breached: list[str] = []
        if metrics.p95_ms > max_p95_ms:
            breached.append(f"p95 {metrics.p95_ms:.1f}ms > {max_p95_ms:.1f}ms")
        if metrics.error_rate > max_error_rate:
            breached.append(f"error_rate {metrics.error_rate:.4f} > {max_error_rate:.4f}")
        if metrics.request_rate < min_request_rate:
            breached.append(f"request_rate {metrics.request_rate:.2f} < {min_request_rate:.2f}")
        return PerformanceAssessment(
            status=ValidationStatus.FAIL if breached else ValidationStatus.PASS,
            metrics=metrics,
            breached_thresholds=breached,
            summary=(
                "Performance thresholds breached."
                if breached
                else "All configured performance thresholds passed."
            ),
        )
