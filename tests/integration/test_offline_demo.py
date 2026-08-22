from pathlib import Path

from ai_qa_automation.demo import run_demo


def test_demo_proves_api_failure_is_not_locator_heal(tmp_path: Path) -> None:
    result = run_demo(tmp_path)
    assert result["classification"]["classification"] == "APPLICATION_DEFECT"
    assert result["regression_selection"]["broadened_due_to_uncertainty"] is True
    assert "smoke::checkout" in result["regression_selection"]["selected"]
