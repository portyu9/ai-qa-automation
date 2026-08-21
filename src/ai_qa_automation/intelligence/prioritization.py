from __future__ import annotations

import math

from ..models import RegressionCandidate, RegressionSelection


class RegressionPrioritizer:
    """Risk-first deterministic scoring with mandatory-coverage fail-safes."""

    def score(self, candidate: RegressionCandidate) -> float:
        score = (
            candidate.changed_component_overlap * 0.24
            + candidate.dependency_overlap * 0.16
            + candidate.historical_failure_rate * 0.10
            + candidate.business_criticality * 0.18
            + candidate.security_criticality * 0.14
            + candidate.safety_criticality * 0.09
            + candidate.regulatory_criticality * 0.09
        )
        if self._is_mandatory(candidate):
            return 1.0
        return round(min(1.0, score), 4)

    def select(
        self,
        candidates: list[RegressionCandidate],
        *,
        dependency_confidence: float,
        selection_threshold: float = 0.42,
    ) -> RegressionSelection:
        if not math.isfinite(dependency_confidence) or not 0.0 <= dependency_confidence <= 1.0:
            raise ValueError("dependency_confidence must be a finite value between 0 and 1")
        if not math.isfinite(selection_threshold) or not 0.0 <= selection_threshold <= 1.0:
            raise ValueError("selection_threshold must be a finite value between 0 and 1")
        broaden = dependency_confidence < 0.7
        if dependency_confidence < 0.5:
            threshold = 0.0  # very low confidence: select all candidates rather than risk an escape
        elif broaden:
            threshold = 0.20
        else:
            threshold = selection_threshold
        selected: list[str] = []
        omitted: list[str] = []
        rationale: dict[str, str] = {}

        for candidate in candidates:
            score = self.score(candidate)
            choose = self._is_mandatory(candidate) or score >= threshold
            bucket = selected if choose else omitted
            bucket.append(candidate.test_id)
            mandatory_text = " mandatory" if self._is_mandatory(candidate) else ""
            rationale[candidate.test_id] = (
                f"risk_score={score:.2f}; threshold={threshold:.2f};{mandatory_text} "
                f"dependency_confidence={dependency_confidence:.2f}"
            ).strip()

        total = max(len(candidates), 1)
        reduction = len(omitted) / total
        return RegressionSelection(
            selected=selected,
            omitted=omitted,
            rationale_by_test=rationale,
            estimated_reduction_ratio=round(reduction, 4),
            confidence=max(0.0, min(1.0, dependency_confidence)),
            broadened_due_to_uncertainty=broaden,
        )

    @staticmethod
    def _is_mandatory(candidate: RegressionCandidate) -> bool:
        return any(
            (
                candidate.mandatory,
                candidate.smoke,
                candidate.security_critical,
                candidate.safety_critical,
                candidate.regulatory_critical,
            )
        )
