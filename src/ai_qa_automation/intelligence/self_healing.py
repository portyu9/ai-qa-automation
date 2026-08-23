from __future__ import annotations

import re

from ..models import FailureClass, HealingProposal, LocatorCandidate, RiskLevel
from ..policy import PolicyEngine
from ..tools.locators import (
    deterministic_locator_semantic_score,
    parse_locator_expression,
)

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
_MIN_AUTONOMOUS_SEMANTIC_SCORE = 0.75
_MIN_AUTONOMOUS_COMPOSITE_SCORE = 0.82


class SelfHealingEngine:
    """Ranks semantic locator repairs while keeping mutation authority deterministic."""

    def rank_candidates(
        self,
        candidates: list[LocatorCandidate],
        *,
        original_locator: str,
    ) -> list[LocatorCandidate]:
        original_spec = parse_locator_expression(original_locator)
        normalized: list[LocatorCandidate] = []
        for candidate in candidates:
            rejected = candidate.rejected_reason
            candidate_spec = parse_locator_expression(candidate.locator)
            if candidate.uniqueness_count != 1:
                rejected = rejected or "candidate is not unique"
            if candidate.strategy not in _STRATEGY_STABILITY:
                rejected = (
                    rejected or "unknown locator strategy is not eligible for autonomous repair"
                )
            if candidate.strategy in {"xpath", "positional"} or re.search(
                r"(?:xpath=|//|:nth-(?:child|of-type)|>>\s*nth=|\[\d+\])",
                candidate.locator,
                re.I,
            ):
                rejected = (
                    rejected or "structural/positional locator is too fragile for autonomous repair"
                )
            if original_spec is None:
                rejected = (
                    rejected
                    or "original locator is outside the supported semantic locator contract"
                )
            if candidate_spec is None or candidate_spec.strategy != candidate.strategy:
                rejected = (
                    rejected
                    or "candidate locator syntax/strategy is not deterministically supported"
                )

            semantic_score = (
                deterministic_locator_semantic_score(original_spec, candidate_spec)
                if original_spec is not None and candidate_spec is not None
                else 0.0
            )
            if semantic_score < _MIN_AUTONOMOUS_SEMANTIC_SCORE:
                rejected = (
                    rejected or "candidate does not preserve enough deterministic semantic intent"
                )

            # Both values below are policy-owned. Model-supplied semantic/stability
            # confidence may help proposal generation, but cannot authorize mutation.
            stability = _STRATEGY_STABILITY.get(candidate.strategy, 0.0)
            normalized.append(
                candidate.model_copy(
                    update={
                        "semantic_match": semantic_score,
                        "stability_score": stability,
                        "rejected_reason": rejected,
                    }
                )
            )
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
        if not evidence_ids:
            return HealingProposal(
                allowed=False,
                risk=RiskLevel.HIGH,
                original_locator=original_locator,
                rationale="No evidence was supplied; an evidence-free repair would be speculative.",
                evidence_ids=[],
            )
        if classification not in {
            FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
            FailureClass.TEST_AUTOMATION_DEFECT,
        }:
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

        ranked = self.rank_candidates(candidates, original_locator=original_locator)
        safe = next(
            (
                candidate
                for candidate in ranked
                if not candidate.rejected_reason
                and candidate.semantic_match >= _MIN_AUTONOMOUS_SEMANTIC_SCORE
                and candidate.score >= _MIN_AUTONOMOUS_COMPOSITE_SCORE
            ),
            None,
        )
        if safe is None:
            return HealingProposal(
                allowed=False,
                risk=RiskLevel.HIGH,
                original_locator=original_locator,
                rationale=(
                    "No unique locator candidate satisfied deterministic syntax, stability, "
                    "and semantic-intent requirements for autonomous repair."
                ),
                evidence_ids=evidence_ids,
            )

        return HealingProposal(
            allowed=True,
            risk=RiskLevel.LOW if safe.score >= 0.9 else RiskLevel.MEDIUM,
            original_locator=original_locator,
            proposed_locator=safe.locator,
            rationale=(
                "Unique semantic candidate selected under deterministic locator policy "
                f"({safe.strategy}, semantic={safe.semantic_match:.2f}, score={safe.score:.2f})."
            ),
            evidence_ids=evidence_ids,
            required_validations=[
                "targeted test rerun",
                "relevant regression",
                "assertion-intent preservation check",
                "before/after evidence capture",
            ],
        )
