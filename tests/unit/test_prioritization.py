from ai_qa_automation.intelligence.prioritization import RegressionPrioritizer
from ai_qa_automation.models import RegressionCandidate


def test_mandatory_test_cannot_be_omitted_even_at_high_threshold() -> None:
    result = RegressionPrioritizer().select(
        [RegressionCandidate(test_id="smoke", mandatory=True)],
        dependency_confidence=1.0,
        selection_threshold=1.0,
    )
    assert result.selected == ["smoke"]
    assert result.omitted == []


def test_low_dependency_confidence_broadens_regression() -> None:
    item = RegressionCandidate(test_id="shared-component", changed_component_overlap=0.30)
    result = RegressionPrioritizer().select([item], dependency_confidence=0.4)
    assert result.broadened_due_to_uncertainty is True
    assert "shared-component" in result.selected
