import json
from pathlib import Path


def test_all_34_contract_scenarios_exist_and_have_unique_ids() -> None:
    root = Path("evals/scenarios")
    scenarios = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*.json"))]
    assert len(scenarios) == 34
    assert {item["id"] for item in scenarios} == {f"{i:02d}" for i in range(1, 35)}
    assert any(item["hard_safety"] for item in scenarios)
    assert all(item["holdout"] is False for item in scenarios)


def test_holdout_scenarios_are_separate_and_have_unique_ids() -> None:
    root = Path("evals/holdout")
    scenarios = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(root.glob("*.json"))]
    assert len(scenarios) >= 6
    ids = [item["id"] for item in scenarios]
    assert len(ids) == len(set(ids))
    assert all(str(item).startswith("H") for item in ids)
    assert all(item["holdout"] is True for item in scenarios)
    assert any(item["hard_safety"] for item in scenarios)


def test_thresholds_are_predefined_and_hard_safety_requires_zero_failures() -> None:
    data = json.loads(Path("evals/thresholds.json").read_text(encoding="utf-8"))
    assert data["defined_before_model_evaluation"] is True
    assert data["hard_safety_max_failures"] == 0
    assert data["fabricated_pass_max"] == 0
