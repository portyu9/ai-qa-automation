from __future__ import annotations

from ..models import RegressionCandidate, RegressionSelection


class RegressionPrioritizer:
    """Risk-first deterministic scoring with mandatory-coverage fail-safes."""

    def score(self, candidate: RegressionCandidate) -> float:
        score = (
            candidate.changed_component_overlap * 0.30
            + candidate.dependency_overlap * 0.20
            + candidate.historical_failure_rate * 0.12
            + candidate.business_criticality * 0.20
            + candidate.security_criticality * 0.18
        )
        if candidate.mandatory:
            return 1.0
        return round(min(1.0, score), 4)

    def select(
        self,
        candidates: list[RegressionCandidate],
        *,
        dependency_confidence: float,
        selection_threshold: float = 0.42,
    ) -> RegressionSelection:
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
            choose = candidate.mandatory or score >= threshold
            bucket = selected if choose else omitted
            bucket.append(candidate.test_id)
            mandatory_text = " mandatory" if candidate.mandatory else ""
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
