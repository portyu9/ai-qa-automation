from ai_qa_automation.intelligence.failure_analysis import FailureAnalyzer
from ai_qa_automation.models import EvidenceItem, EvidenceKind, FailureClass


def ev(kind: EvidenceKind, **data: object) -> EvidenceItem:
    return EvidenceItem(
        run_id="run",
        kind=kind,
        source="test",
        summary="fixture",
        structured_data=data,
    )


def locator_verification(candidate_locator: str, strategy: str) -> list[EvidenceItem]:
    source_identifier = "https://example.test/profile"
    verification = EvidenceItem(
        run_id="run",
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="playwright_locator_verification",
        source_identifier=source_identifier,
        summary="verified",
        structured_data={
            "original_locator": "get_by_test_id('save-profile-button')",
            "original_count": 0,
            "candidates": [
                {
                    "locator": candidate_locator,
                    "strategy": strategy,
                    "uniqueness_count": 1,
                    "rejected_reason": None,
                }
            ],
        },
    )
    context = EvidenceItem(
        run_id="run",
        kind=EvidenceKind.ACCESSIBILITY_SNAPSHOT,
        source="playwright_locator_verification",
        source_identifier=source_identifier,
        summary="context",
    )
    return [verification, context]


def test_api_500_is_application_defect_not_locator_guess() -> None:
    result = FailureAnalyzer().classify([ev(EvidenceKind.HTTP_RESPONSE, status_code=500)])
    assert result.classification is FailureClass.APPLICATION_DEFECT
    assert result.evidence_ids


def test_auth_failure_is_classified_from_observed_status() -> None:
    result = FailureAnalyzer().classify([ev(EvidenceKind.HTTP_RESPONSE, status_code=403)])
    assert result.classification is FailureClass.AUTHENTICATION_FAILURE


def test_semantic_control_present_plus_locator_failure_is_contract_change() -> None:
    result = FailureAnalyzer().classify(
        [
            ev(
                EvidenceKind.ACCESSIBILITY_SNAPSHOT,
                expected_control_present=True,
                locator_failed=True,
            )
        ]
    )
    assert result.classification is FailureClass.LOCATOR_UI_CONTRACT_CHANGE


def test_playwright_unique_semantic_candidate_supports_locator_contract_change() -> None:
    result = FailureAnalyzer().classify(
        locator_verification(
            "get_by_role('button', name='Save Profile')",
            "role_name",
        )
    )
    assert result.classification is FailureClass.LOCATOR_UI_CONTRACT_CHANGE


def test_unique_but_semantically_unrelated_candidate_does_not_prove_locator_contract_change() -> (
    None
):
    result = FailureAnalyzer().classify(
        locator_verification(
            "get_by_role('button', name='Delete Account')",
            "role_name",
        )
    )
    assert result.classification is FailureClass.INSUFFICIENT_EVIDENCE


def test_no_discriminating_evidence_never_fabricates_cause() -> None:
    result = FailureAnalyzer().classify(
        [ev(EvidenceKind.SOURCE_OBSERVATION, symptom="button missing")]
    )
    assert result.classification is FailureClass.INSUFFICIENT_EVIDENCE
