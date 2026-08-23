import json
import shutil
from pathlib import Path

import pytest

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
        item.id == PRIMARY_EVALUATORS[item.evaluator].case_id
        and item.title == PRIMARY_EVALUATORS[item.evaluator].title
        and item.expected == PRIMARY_EVALUATORS[item.evaluator].expected
        and item.hard_safety is PRIMARY_EVALUATORS[item.evaluator].hard_safety
        for item in scenarios
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "misleading replacement title"),
        ("expected", "PASS"),
        ("hard_safety", True),
        ("evaluator", "classifier_test_framework"),
    ],
)
def test_primary_catalog_contract_drift_fails_closed(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    path = directory / "01.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = value
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_primary_scenarios(directory)


def test_primary_scenario_id_must_match_filename(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    (directory / "01.json").rename(directory / "35.json")

    with pytest.raises(ValueError, match="does not match filename"):
        load_primary_scenarios(directory)


def test_repository_visible_readiness_cases_are_sequestered_and_distinct() -> None:
    scenarios = load_readiness_scenarios()

    assert len(scenarios) == 6
    assert {item.id for item in scenarios} == {f"H{i:02d}" for i in range(1, 7)}
    assert len({item.evaluator for item in scenarios}) == len(scenarios)
    assert set(item.evaluator for item in scenarios) == set(READINESS_EVALUATORS)
    assert len({spec.function for spec in READINESS_EVALUATORS.values()}) == len(
        READINESS_EVALUATORS
    )
    assert all(item.holdout is True for item in scenarios)
    assert all(item.repository_visible is True for item in scenarios)
    assert any(item.hard_safety for item in scenarios)
    assert all(
        item.id == READINESS_EVALUATORS[item.evaluator].case_id
        and item.title == READINESS_EVALUATORS[item.evaluator].title
        and item.expected == READINESS_EVALUATORS[item.evaluator].expected
        and item.hard_safety is READINESS_EVALUATORS[item.evaluator].hard_safety
        for item in scenarios
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("title", "misleading replacement title"),
        ("expected", "PASS"),
        ("hard_safety", False),
        ("repository_visible", False),
    ],
)
def test_readiness_catalog_contract_drift_fails_closed(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    directory = tmp_path / "readiness"
    shutil.copytree(Path("evals/holdout"), directory)
    path = directory / "H02.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data[field] = value
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_readiness_scenarios(directory)


def test_readiness_scenario_id_must_match_filename(tmp_path: Path) -> None:
    directory = tmp_path / "readiness"
    shutil.copytree(Path("evals/holdout"), directory)
    (directory / "H01.json").rename(directory / "H99.json")

    with pytest.raises(ValueError, match="does not match filename"):
        load_readiness_scenarios(directory)


def test_thresholds_are_predefined_and_hard_safety_requires_zero_failures() -> None:
    data = json.loads(Path("evals/thresholds.json").read_text(encoding="utf-8"))
    assert data["defined_before_model_evaluation"] is True
    assert data["hard_safety_max_failures"] == 0
    assert data["fabricated_pass_max"] == 0
