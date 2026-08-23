import json
from pathlib import Path

from evals.holdout_runner import READINESS_EVALUATORS, load_readiness_scenarios
from evals.runner import PRIMARY_EVALUATORS, load_primary_scenarios


def test_all_34_primary_cases_have_unique_ids_and_execution_paths() -> None:
    scenarios = load_primary_scenarios()

    assert len(scenarios) == 34
    assert {item.id for item in scenarios} == {f"{i:02d}" for i in range(1, 35)}
    assert len({item.evaluator for item in scenarios}) == 34
    assert set(item.evaluator for item in scenarios) == set(PRIMARY_EVALUATORS)
    assert len({spec.function for spec in PRIMARY_EVALUATORS.values()}) == 34
    assert any(item.hard_safety for item in scenarios)
    assert all(item.holdout is False for item in scenarios)
    assert all(
        item.expected == PRIMARY_EVALUATORS[item.evaluator].expected
        and item.hard_safety is PRIMARY_EVALUATORS[item.evaluator].hard_safety
        for item in scenarios
    )


def test_repository_visible_readiness_cases_are_sequestered_and_distinct() -> None:
    scenarios = load_readiness_scenarios()

    assert len(scenarios) >= 6
    ids = [item.id for item in scenarios]
    assert len(ids) == len(set(ids))
    assert all(item.startswith("H") for item in ids)
    assert len({item.evaluator for item in scenarios}) == len(scenarios)
    assert set(item.evaluator for item in scenarios) == set(READINESS_EVALUATORS)
    assert len({spec.function for spec in READINESS_EVALUATORS.values()}) == len(
        READINESS_EVALUATORS
    )
    assert all(item.holdout is True for item in scenarios)
    assert all(item.repository_visible is True for item in scenarios)
    assert any(item.hard_safety for item in scenarios)
    assert all(
        item.expected == READINESS_EVALUATORS[item.evaluator].expected
        and item.hard_safety is READINESS_EVALUATORS[item.evaluator].hard_safety
        for item in scenarios
    )


def test_thresholds_are_predefined_and_hard_safety_requires_zero_failures() -> None:
    data = json.loads(Path("evals/thresholds.json").read_text(encoding="utf-8"))
    assert data["defined_before_model_evaluation"] is True
    assert data["hard_safety_max_failures"] == 0
    assert data["fabricated_pass_max"] == 0
