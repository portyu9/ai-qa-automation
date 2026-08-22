from __future__ import annotations

from collections import Counter

from ..models import (
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    FailureClass,
    FailureClassificationResult,
    Hypothesis,
)
from ..tools.locators import deterministic_locator_semantic_score, parse_locator_expression

_MIN_LOCATOR_SEMANTIC_SCORE = 0.75


class FailureAnalyzer:
    """Deterministic first-pass classifier; Claude may reason over the same evidence afterward."""

    def classify(self, evidence: list[EvidenceItem]) -> FailureClassificationResult:
        observed = [item for item in evidence if item.nature == EvidenceNature.OBSERVED_FACT]
        if not observed:
            return self._result(
                FailureClass.INSUFFICIENT_EVIDENCE,
                1.0,
                "No observed facts were available; model interpretation cannot prove a failure class.",
                [],
            )

        ids = [item.id for item in observed]
        signals: Counter[FailureClass] = Counter()
        rationale: dict[FailureClass, list[str]] = {}

        def add(category: FailureClass, weight: int, reason: str) -> None:
            signals[category] += weight
            rationale.setdefault(category, []).append(reason)

        for item in observed:
            data = item.structured_data
            if item.kind == EvidenceKind.HTTP_RESPONSE:
                status = int(data.get("status_code", 0) or 0)
                if status in {401, 403}:
                    add(FailureClass.AUTHENTICATION_FAILURE, 7, f"HTTP {status} observed")
                elif status >= 500:
                    if data.get("external_dependency"):
                        add(
                            FailureClass.EXTERNAL_DEPENDENCY_FAILURE, 7, f"dependency HTTP {status}"
                        )
                    else:
                        add(FailureClass.APPLICATION_DEFECT, 6, f"application HTTP {status}")
                elif status == 422 or data.get("invalid_test_data"):
                    add(FailureClass.TEST_DATA_FAILURE, 5, "input/test data rejected")

            if item.kind in {EvidenceKind.DOM_SNAPSHOT, EvidenceKind.ACCESSIBILITY_SNAPSHOT}:
                if data.get("expected_control_present") and data.get("locator_failed"):
                    add(
                        FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
                        8,
                        "expected semantic control exists but locator failed",
                    )
                if data.get("expected_control_absent") and data.get("business_state_expected"):
                    add(FailureClass.APPLICATION_DEFECT, 5, "expected control/behavior is absent")

            if (
                item.kind == EvidenceKind.SOURCE_OBSERVATION
                and item.source == "playwright_locator_verification"
            ):
                original_count = int(data.get("original_count", -1))
                original_spec = parse_locator_expression(str(data.get("original_locator") or ""))
                stable_semantic_unique = []
                if original_spec is not None:
                    for row in data.get("candidates", []):
                        if not isinstance(row, dict):
                            continue
                        strategy = str(row.get("strategy") or "")
                        candidate_spec = parse_locator_expression(str(row.get("locator") or ""))
                        if (
                            int(row.get("uniqueness_count", 0) or 0) != 1
                            or row.get("rejected_reason")
                            or strategy
                            not in {"test_id", "role_name", "label", "placeholder", "exact_text"}
                            or candidate_spec is None
                            or candidate_spec.strategy != strategy
                        ):
                            continue
                        semantic_score = deterministic_locator_semantic_score(
                            original_spec,
                            candidate_spec,
                        )
                        if semantic_score >= _MIN_LOCATOR_SEMANTIC_SCORE:
                            stable_semantic_unique.append(row)
                same_page_context = any(
                    other.id != item.id
                    and other.source_identifier == item.source_identifier
                    and other.kind
                    in {
                        EvidenceKind.SCREENSHOT,
                        EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                        EvidenceKind.DOM_SNAPSHOT,
                    }
                    for other in observed
                )
                if original_count == 0 and stable_semantic_unique and same_page_context:
                    add(
                        FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
                        8,
                        "Playwright observed the original locator missing while a unique stable candidate preserved deterministic semantic intent in the same evidenced page state",
                    )

            if item.kind == EvidenceKind.EXCEPTION:
                code = str(data.get("code", "")).lower()
                if "timeout" in code or data.get("timeout"):
                    add(FailureClass.FLAKINESS_TIMING, 3, "timing/timeout symptom observed")
                if data.get("test_framework_error"):
                    add(FailureClass.TEST_AUTOMATION_DEFECT, 6, "test-framework error observed")
                if data.get("configuration_error"):
                    add(FailureClass.CONFIGURATION_FAILURE, 7, "configuration error observed")

            if item.kind == EvidenceKind.NETWORK_ERROR:
                if data.get("external_dependency"):
                    add(
                        FailureClass.EXTERNAL_DEPENDENCY_FAILURE,
                        6,
                        "external network dependency failed",
                    )
                elif data.get("environment_unreachable"):
                    add(FailureClass.ENVIRONMENT_FAILURE, 6, "target environment unreachable")

            if item.kind == EvidenceKind.PERFORMANCE_METRIC and data.get("threshold_breached"):
                add(FailureClass.PERFORMANCE_REGRESSION, 8, "performance threshold breached")

            if data.get("eventual_pass_without_change"):
                add(FailureClass.FLAKINESS_TIMING, 6, "rerun passed without code/data change")
            if data.get("environment_failure"):
                add(FailureClass.ENVIRONMENT_FAILURE, 7, "environment failure explicitly observed")

        if not signals:
            return self._result(
                FailureClass.INSUFFICIENT_EVIDENCE,
                0.95,
                "Observed evidence does not discriminate between plausible causes.",
                ids,
                self._default_hypotheses(ids),
            )

        ranked = signals.most_common()
        top, score = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else 0
        confidence = min(0.98, max(0.55, 0.58 + (score - runner_up) * 0.06))
        competing = [
            Hypothesis(
                id=f"H{i + 1}",
                statement=category.value,
                confidence=min(0.9, points / max(score, 1)),
                supporting_evidence_ids=ids,
                next_discriminating_action="Collect a different evidence type before modifying tests.",
            )
            for i, (category, points) in enumerate(ranked[1:4])
        ]
        return self._result(top, confidence, "; ".join(rationale[top]), ids, competing)

    @staticmethod
    def _result(
        classification: FailureClass,
        confidence: float,
        rationale: str,
        evidence_ids: list[str],
        hypotheses: list[Hypothesis] | None = None,
    ) -> FailureClassificationResult:
        return FailureClassificationResult(
            classification=classification,
            confidence=confidence,
            rationale=rationale,
            evidence_ids=evidence_ids,
            competing_hypotheses=hypotheses or [],
        )

    @staticmethod
    def _default_hypotheses(ids: list[str]) -> list[Hypothesis]:
        return [
            Hypothesis(
                id="H1",
                statement="APPLICATION_DEFECT",
                confidence=0.25,
                supporting_evidence_ids=ids,
            ),
            Hypothesis(
                id="H2",
                statement="TEST_AUTOMATION_DEFECT",
                confidence=0.25,
                supporting_evidence_ids=ids,
            ),
            Hypothesis(
                id="H3",
                statement="ENVIRONMENT_FAILURE",
                confidence=0.25,
                supporting_evidence_ids=ids,
            ),
            Hypothesis(
                id="H4",
                statement="TEST_DATA_FAILURE",
                confidence=0.25,
                supporting_evidence_ids=ids,
            ),
        ]
