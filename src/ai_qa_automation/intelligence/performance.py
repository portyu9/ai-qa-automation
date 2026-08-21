from __future__ import annotations

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
            summary="Performance thresholds breached." if breached else "All configured performance thresholds passed.",
        )
