from __future__ import annotations

from ai_qa_automation.models import (
    LocatorCandidate,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.runtime.browser_validation import (
    browser_inspection_subject,
    browser_locator_verification_subject,
    browser_validation_result,
)
from ai_qa_automation.runtime.validation_truth import determine_terminal_outcome


def candidate(
    locator: str,
    strategy: str,
    *,
    uniqueness_count: int = 0,
    semantic_match: float = 0.0,
    stability_score: float = 0.5,
    rejected_reason: str | None = None,
) -> LocatorCandidate:
    return LocatorCandidate(
        locator=locator,
        strategy=strategy,
        uniqueness_count=uniqueness_count,
        semantic_match=semantic_match,
        stability_score=stability_score,
        rejected_reason=rejected_reason,
    )


def test_browser_inspection_gate_binds_exact_requested_url_without_persisting_query() -> None:
    first = browser_inspection_subject("https://example.test/checkout?token=top-secret")
    same = browser_inspection_subject("https://example.test/checkout?token=top-secret")
    different = browser_inspection_subject("https://example.test/cart?token=top-secret")

    assert first.gate_id == same.gate_id
    assert first.gate_id != different.gate_id
    assert first.name == "browser_inspection"
    assert len(first.gate_id.removeprefix("browser_inspection:")) == 64
    assert first.details["requested_host"] == "example.test"
    assert first.details["requested_scheme"] == "https"
    assert "top-secret" not in repr(first.details)
    assert "checkout" not in repr(first.details)


def test_locator_gate_binds_exact_candidate_request_without_persisting_locator_text() -> None:
    first_candidates = [
        candidate('[data-testid="login"]', "semantic_css", uniqueness_count=99),
        candidate('page.get_by_text("Sign in", exact=True)', "exact_text"),
    ]
    first = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        first_candidates,
    )
    same = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        first_candidates,
    )
    reordered = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        list(reversed(first_candidates)),
    )
    changed_model_claim = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        [
            candidate(
                '[data-testid="login"]',
                "semantic_css",
                uniqueness_count=1,
                semantic_match=1.0,
                stability_score=1.0,
                rejected_reason="model advisory rejection",
            ),
            candidate('page.get_by_text("Sign in", exact=True)', "exact_text"),
        ],
    )
    changed_locator = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        [candidate('[data-testid="submit"]', "semantic_css")],
    )

    assert first.gate_id == same.gate_id
    assert first.gate_id != reordered.gate_id
    assert first.gate_id != changed_model_claim.gate_id
    assert first.gate_id != changed_locator.gate_id
    assert len(first.gate_id.removeprefix("browser_locator_verification:")) == 64
    assert first.details["candidate_count"] == 2
    assert str(first.details["candidate_request_hash"]).startswith("sha256:")
    assert "Sign in" not in repr(first.details)
    assert "/login" not in repr(first.details)
    assert "data-testid" not in repr(first.details)


def test_locator_duplicate_request_is_not_conflated_with_single_candidate_request() -> None:
    item = candidate('page.get_by_test_id("login")', "test_id")
    single = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        [item],
    )
    duplicate = browser_locator_verification_subject(
        "https://example.test/login",
        'page.get_by_role("button", name="Sign in")',
        [item, item],
    )

    assert single.gate_id != duplicate.gate_id
    assert single.details["candidate_count"] == 1
    assert duplicate.details["candidate_count"] == 2


def test_unrelated_browser_pass_cannot_close_different_browser_objective() -> None:
    observed = browser_inspection_subject("https://example.test/a")
    objective = browser_inspection_subject("https://example.test/b")
    validation = browser_validation_result(
        observed,
        revision=0,
        status=ValidationStatus.PASS,
        summary="observed A",
    )

    status, reason = determine_terminal_outcome(
        "success",
        [validation],
        current_revision=0,
        objective_gate_id=objective.gate_id,
    )

    assert status is TerminalStatus.NOT_VERIFIED
    assert "no active PASS matched" in reason


def test_later_same_subject_browser_uncertainty_prevents_stale_pass() -> None:
    subject = browser_inspection_subject("https://example.test/checkout")
    passed = browser_validation_result(
        subject,
        revision=0,
        status=ValidationStatus.PASS,
        summary="browser passed",
    )
    unavailable = browser_validation_result(
        subject,
        revision=0,
        status=ValidationStatus.NOT_VERIFIED,
        summary="browser became unavailable",
    )

    status, reason = determine_terminal_outcome(
        "success",
        [passed, unavailable],
        current_revision=0,
        objective_gate_id=subject.gate_id,
    )

    assert status is TerminalStatus.NOT_VERIFIED
    assert "incomplete" in reason.casefold()


def test_legacy_unbound_browser_runtime_gate_cannot_close_objective() -> None:
    legacy = ValidationResult(
        name="browser_runtime",
        gate_id="browser_runtime",
        revision=0,
        status=ValidationStatus.PASS,
        summary="legacy browser capability green",
    )

    status, reason = determine_terminal_outcome(
        "success",
        [legacy],
        current_revision=0,
        objective_gate_id="browser_runtime",
    )

    assert status is TerminalStatus.NOT_VERIFIED
    assert "legacy validation gate" in reason
    assert "exact deterministic subject" in reason
