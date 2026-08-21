from __future__ import annotations

from ai_qa_automation.intelligence.change_impact import ChangeImpactAnalyzer
from ai_qa_automation.models import RiskLevel, TestLayer


def test_no_observed_changes_remains_conservative() -> None:
    result = ChangeImpactAnalyzer().assess([])

    assert result.risk is RiskLevel.LOW
    assert result.changed_files == ()
    assert result.recommended_layers == (TestLayer.UNIT,)
    assert result.recommended_tags == ("smoke",)
    assert result.confidence < 0.5


def test_security_change_broadens_to_critical_regression() -> None:
    result = ChangeImpactAnalyzer().assess(["src/security/auth_policy.py"])

    assert result.risk is RiskLevel.CRITICAL
    assert "security" in result.risk_areas
    assert TestLayer.INTEGRATION in result.recommended_layers
    assert "security" in result.recommended_tags
    assert "full-regression" in result.recommended_tags
    assert any("critical security" in reason for reason in result.rationale)


def test_api_contract_change_selects_contract_and_integration_layers() -> None:
    result = ChangeImpactAnalyzer().assess(["openapi/service.yaml"])

    assert result.risk is RiskLevel.HIGH
    assert "api_contract" in result.risk_areas
    assert TestLayer.API in result.recommended_layers
    assert TestLayer.INTEGRATION in result.recommended_layers
    assert "contract" in result.recommended_tags
    assert "full-regression" in result.recommended_tags


def test_ui_change_selects_component_and_ui_layers() -> None:
    result = ChangeImpactAnalyzer().assess(["frontend/components/CheckoutButton.tsx"])

    assert result.risk is RiskLevel.MEDIUM
    assert "ui" in result.risk_areas
    assert TestLayer.COMPONENT in result.recommended_layers
    assert TestLayer.UI in result.recommended_layers
    assert "ui" in result.recommended_tags


def test_documentation_only_change_stays_low_risk() -> None:
    result = ChangeImpactAnalyzer().assess(["docs/OPERATIONS.md", "README.md"])

    assert result.risk is RiskLevel.LOW
    assert result.risk_areas == ("documentation",)
    assert "full-regression" not in result.recommended_tags
