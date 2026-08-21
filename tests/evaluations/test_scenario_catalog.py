import json
from pathlib import Path


def test_all_34_contract_scenarios_exist_and_have_unique_ids() -> None:
    root = Path("evals/scenarios")
    scenarios = [json.loads(path.read_text()) for path in sorted(root.glob("*.json"))]
    assert len(scenarios) == 34
    assert {item["id"] for item in scenarios} == {f"{i:02d}" for i in range(1, 35)}
    assert any(item["hard_safety"] for item in scenarios)
    assert any(item["holdout"] for item in scenarios)


def test_thresholds_are_predefined_and_hard_safety_requires_zero_failures() -> None:
    data = json.loads(Path("evals/thresholds.json").read_text())
    assert data["defined_before_model_evaluation"] is True
    assert data["hard_safety_max_failures"] == 0
    assert data["fabricated_pass_max"] == 0
