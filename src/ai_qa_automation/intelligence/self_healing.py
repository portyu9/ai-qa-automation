from __future__ import annotations

import re

from ..models import FailureClass, HealingProposal, LocatorCandidate, RiskLevel
from ..policy import PolicyEngine

_STRATEGY_STABILITY = {
    "test_id": 1.0,
    "role_name": 0.95,
    "label": 0.9,
    "placeholder": 0.78,
    "exact_text": 0.72,
    "semantic_css": 0.55,
    "xpath": 0.35,
    "positional": 0.05,
}


class SelfHealingEngine:
    """Ranks semantic locator repairs and blocks intent-eroding patches."""

    def rank_candidates(self, candidates: list[LocatorCandidate]) -> list[LocatorCandidate]:
        normalized: list[LocatorCandidate] = []
        for candidate in candidates:
            rejected = candidate.rejected_reason
            if candidate.uniqueness_count != 1:
                rejected = rejected or "candidate is not unique"
            if candidate.strategy == "positional" or re.search(r":nth-child|\[\d+\]", candidate.locator):
                rejected = rejected or "positional locator is fragile"
            stability = max(candidate.stability_score, _STRATEGY_STABILITY.get(candidate.strategy, 0.4))
            normalized.append(candidate.model_copy(update={"stability_score": stability, "rejected_reason": rejected}))
        return sorted(normalized, key=lambda item: item.score, reverse=True)

    def propose(
        self,
        *,
        classification: FailureClass,
        original_locator: str,
        candidates: list[LocatorCandidate],
        evidence_ids: list[str],
        policy: PolicyEngine,
        proposed_diff: str = "",
    ) -> HealingProposal:
        if classification not in {FailureClass.LOCATOR_UI_CONTRACT_CHANGE, FailureClass.TEST_AUTOMATION_DEFECT}:
            return HealingProposal(
                allowed=False,
                risk=RiskLevel.HIGH,
                original_locator=original_locator,
                rationale="Failure classification does not support a test-side locator repair.",
                evidence_ids=evidence_ids,
            )

        violations = policy.validate_patch(proposed_diff) if proposed_diff else []
        if violations:
            return HealingProposal(
                allowed=False,
                risk=RiskLevel.CRITICAL,
                original_locator=original_locator,
                rationale=f"Patch violates test-intent safeguards: {', '.join(violations)}.",
                evidence_ids=evidence_ids,
            )

        ranked = self.rank_candidates(candidates)
        safe = next((candidate for candidate in ranked if not candidate.rejected_reason and candidate.score >= 0.82), None)
        if safe is None:
            return HealingProposal(
                allowed=False,
                risk=RiskLevel.HIGH,
                original_locator=original_locator,
                rationale="No unique high-confidence semantic locator candidate was proven.",
                evidence_ids=evidence_ids,
            )

        return HealingProposal(
            allowed=True,
            risk=RiskLevel.LOW if safe.score >= 0.9 else RiskLevel.MEDIUM,
            original_locator=original_locator,
            proposed_locator=safe.locator,
            rationale=f"Unique semantic candidate selected ({safe.strategy}, score={safe.score:.2f}).",
            evidence_ids=evidence_ids,
            required_validations=[
                "targeted test rerun",
                "relevant regression",
                "assertion-intent preservation check",
                "before/after evidence capture",
            ],
        )
