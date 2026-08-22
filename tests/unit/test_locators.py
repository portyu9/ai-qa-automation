from __future__ import annotations

import pytest

from ai_qa_automation.tools.locators import (
    deterministic_locator_semantic_score,
    locator_semantic_tokens,
    parse_locator_expression,
)


@pytest.mark.parametrize(
    ("expression", "strategy"),
    [
        ("get_by_test_id('save-profile-button')", "test_id"),
        ("page.get_by_role('button', name='Save Profile')", "role_name"),
        ("get_by_label('Email Address')", "label"),
        ("get_by_placeholder('Search users')", "placeholder"),
        ("get_by_text('Continue', exact=True)", "exact_text"),
        ("locator('[data-action=save]')", "semantic_css"),
        ("page.getByRole('button', { name: 'Save Profile', exact: true })", "role_name"),
    ],
)
def test_supported_literal_locator_contracts_parse(expression: str, strategy: str) -> None:
    spec = parse_locator_expression(expression)
    assert spec is not None
    assert spec.strategy == strategy


@pytest.mark.parametrize(
    "expression",
    [
        "page.locator(dynamic_selector)",
        "page.get_by_role(role, name=name)",
        "page.locator('//button[1]')\npage.click()",
        "",
    ],
)
def test_dynamic_or_multiline_locator_contracts_are_rejected(expression: str) -> None:
    assert parse_locator_expression(expression) is None


def test_semantic_tokens_normalize_test_id_and_accessible_name() -> None:
    test_id = parse_locator_expression("get_by_test_id('save-profile-button')")
    role = parse_locator_expression("get_by_role('button', name='Save Profile')")
    assert test_id is not None and role is not None
    assert {"save", "profile", "button"} <= locator_semantic_tokens(test_id)
    assert {"save", "profile", "button"} <= locator_semantic_tokens(role)


def test_related_locator_contracts_receive_high_deterministic_semantic_score() -> None:
    original = parse_locator_expression("get_by_test_id('save-profile-button')")
    candidate = parse_locator_expression("get_by_role('button', name='Save Profile')")
    assert original is not None and candidate is not None
    assert deterministic_locator_semantic_score(original, candidate) >= 0.9


def test_unrelated_unique_element_cannot_inherit_model_semantic_confidence() -> None:
    original = parse_locator_expression("get_by_test_id('save-profile-button')")
    candidate = parse_locator_expression("get_by_role('button', name='Delete Account')")
    assert original is not None and candidate is not None
    assert deterministic_locator_semantic_score(original, candidate) < 0.75


def test_same_strategy_gets_only_small_policy_bonus_not_automatic_approval() -> None:
    original = parse_locator_expression("get_by_test_id('save-profile')")
    candidate = parse_locator_expression("get_by_test_id('delete-account')")
    assert original is not None and candidate is not None
    assert deterministic_locator_semantic_score(original, candidate) == 0.0


def test_partial_semantic_overlap_is_conservative() -> None:
    original = parse_locator_expression("get_by_test_id('checkout-submit-button')")
    candidate = parse_locator_expression("get_by_role('button', name='Submit Order')")
    assert original is not None and candidate is not None
    score = deterministic_locator_semantic_score(original, candidate)
    assert 0 < score < 1
