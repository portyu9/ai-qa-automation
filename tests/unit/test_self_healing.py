from pathlib import Path

from ai_qa_automation.intelligence.self_healing import SelfHealingEngine
from ai_qa_automation.models import FailureClass, LocatorCandidate, RiskLevel
from ai_qa_automation.policy import PolicyEngine


def policy(tmp_path: Path) -> PolicyEngine:
    target = tmp_path / "target"
    target.mkdir()
    return PolicyEngine(tmp_path, target, allow_test_writes=True)


def test_prefers_unique_semantic_role_locator(tmp_path: Path) -> None:
    candidates = [
        LocatorCandidate(locator=".card > div:nth-child(3)", strategy="positional", uniqueness_count=1, semantic_match=0.8, stability_score=0.1),
        LocatorCandidate(locator="get_by_role('button', name='Place Order')", strategy="role_name", uniqueness_count=1, semantic_match=0.98, stability_score=0.9),
    ]
    proposal = SelfHealingEngine().propose(
        classification=FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
        original_locator=".generated-9182",
        candidates=candidates,
        evidence_ids=["ev-1"],
        policy=policy(tmp_path),
        proposed_diff="+page.get_by_role('button', name='Place Order').click()\n",
    )
    assert proposal.allowed is True
    assert proposal.risk in {RiskLevel.LOW, RiskLevel.MEDIUM}
    assert proposal.proposed_locator == "get_by_role('button', name='Place Order')"


def test_non_unique_locator_is_not_healed(tmp_path: Path) -> None:
    candidate = LocatorCandidate(locator="get_by_text('Submit')", strategy="exact_text", uniqueness_count=3, semantic_match=0.99, stability_score=0.9)
    proposal = SelfHealingEngine().propose(
        classification=FailureClass.LOCATOR_UI_CONTRACT_CHANGE,
        original_locator="#submit",
        candidates=[candidate],
        evidence_ids=["ev-1"],
        policy=policy(tmp_path),
    )
    assert proposal.allowed is False


def test_assertion_removal_blocks_otherwise_valid_heal(tmp_path: Path) -> None:
    candidate = LocatorCandidate(locator="get_by_test_id('save')", strategy="test_id", uniqueness_count=1, semantic_match=1, stability_score=1)
    proposal = SelfHealingEngine().propose(
        classification=FailureClass.TEST_AUTOMATION_DEFECT,
        original_locator="#old",
        candidates=[candidate],
        evidence_ids=["ev-1"],
        policy=policy(tmp_path),
        proposed_diff="-assert response.status_code == 201\n+page.get_by_test_id('save').click()\n",
    )
    assert proposal.allowed is False
    assert proposal.risk is RiskLevel.CRITICAL
