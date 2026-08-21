from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .evidence import EvidenceStore
from .intelligence.failure_analysis import FailureAnalyzer
from .intelligence.prioritization import RegressionPrioritizer
from .models import EvidenceItem, EvidenceKind, RegressionCandidate


def run_demo(root: Path) -> dict[str, object]:
    """Offline proof: API 500 causing a missing UI control must not be 'healed' as a locator defect."""
    run_id = f"demo-api-failure-{uuid4().hex[:8]}"
    evidence = EvidenceStore(root / "artifacts", run_id)
    api = evidence.add(
        EvidenceItem(
            run_id=run_id,
            kind=EvidenceKind.HTTP_RESPONSE,
            source="reference-sut",
            summary="Order API returned server error",
            structured_data={"status_code": 500, "endpoint": "/api/order"},
        )
    )
    dom = evidence.add(
        EvidenceItem(
            run_id=run_id,
            kind=EvidenceKind.DOM_SNAPSHOT,
            source="reference-sut",
            summary="Order form not rendered after API error",
            structured_data={"expected_control_absent": True, "business_state_expected": True},
        )
    )
    classification = FailureAnalyzer().classify([api, dom])

    candidates = [
        RegressionCandidate(test_id="smoke::checkout", mandatory=True, business_criticality=1.0),
        RegressionCandidate(test_id="api::orders", changed_component_overlap=1.0, dependency_overlap=0.9, business_criticality=0.9),
        RegressionCandidate(test_id="ui::profile", changed_component_overlap=0.05, dependency_overlap=0.05),
    ]
    selection = RegressionPrioritizer().select(candidates, dependency_confidence=0.5)
    return {
        "classification": classification.model_dump(mode="json"),
        "regression_selection": selection.model_dump(mode="json"),
        "proof": "API/application evidence wins over a tempting locator-only repair.",
    }
