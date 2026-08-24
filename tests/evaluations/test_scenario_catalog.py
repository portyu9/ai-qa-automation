import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import ai_qa_automation.io_safety as io_safety
from ai_qa_automation.io_safety import read_json_object_bounded
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


def test_primary_catalog_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    path = directory / "01.json"
    path.write_text(
        '{"id":"01","title":"real application defect","evaluator":"classifier",'
        '"expected":"APPLICATION_DEFECT","expected":"PASS","hard_safety":false,'
        '"holdout":false}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_primary_scenarios(directory)


def test_primary_catalog_rejects_coercive_boolean_types(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    path = directory / "01.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["hard_safety"] = 0
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValidationError):
        load_primary_scenarios(directory)


def test_primary_catalog_rejects_symlinked_fixture(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    external = tmp_path / "external.json"
    shutil.copyfile(directory / "01.json", external)
    (directory / "01.json").unlink()
    (directory / "01.json").symlink_to(external)

    with pytest.raises(ValueError, match="regular non-symlink file"):
        load_primary_scenarios(directory)


def test_primary_catalog_rejects_symlinked_directory(tmp_path: Path) -> None:
    real_directory = tmp_path / "primary-real"
    shutil.copytree(Path("evals/scenarios"), real_directory)
    linked_directory = tmp_path / "primary-linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(ValueError, match="is a symlink"):
        load_primary_scenarios(linked_directory)


def test_primary_catalog_enforces_actual_ingestion_bound(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    path = directory / "01.json"
    path.write_text("{" + '"padding":"' + ("x" * (64 * 1024)) + '"}', encoding="utf-8")

    with pytest.raises(ValueError, match="ingestion limit"):
        load_primary_scenarios(directory)


def test_primary_catalog_enforces_enumeration_bound_during_scan(tmp_path: Path) -> None:
    directory = tmp_path / "primary"
    shutil.copytree(Path("evals/scenarios"), directory)
    for index in range(31):
        (directory / f"junk-{index:02d}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="entry ingestion limit"):
        load_primary_scenarios(directory)


def _swap_directory_when_scandir_starts(
    directory: Path,
    external: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_scandir = io_safety.os.scandir
    swapped = False

    def swapping_scandir(path: Any) -> Any:
        nonlocal swapped
        if not swapped and isinstance(path, int):
            swapped = True
            preserved = directory.with_name(f"{directory.name}-preserved")
            directory.rename(preserved)
            directory.symlink_to(external, target_is_directory=True)
        return original_scandir(path)

    monkeypatch.setattr(io_safety.os, "scandir", swapping_scandir)


def test_primary_catalog_rejects_directory_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "primary"
    external = tmp_path / "external"
    shutil.copytree(Path("evals/scenarios"), directory)
    shutil.copytree(Path("evals/scenarios"), external)
    _swap_directory_when_scandir_starts(directory, external, monkeypatch)

    with pytest.raises(ValueError, match="changed|symlink"):
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


def test_readiness_catalog_rejects_symlinked_directory(tmp_path: Path) -> None:
    real_directory = tmp_path / "readiness-real"
    shutil.copytree(Path("evals/holdout"), real_directory)
    linked_directory = tmp_path / "readiness-linked"
    linked_directory.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(ValueError, match="is a symlink"):
        load_readiness_scenarios(linked_directory)


def test_readiness_catalog_rejects_directory_swap_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "readiness"
    external = tmp_path / "external"
    shutil.copytree(Path("evals/holdout"), directory)
    shutil.copytree(Path("evals/holdout"), external)
    _swap_directory_when_scandir_starts(directory, external, monkeypatch)

    with pytest.raises(ValueError, match="changed|symlink"):
        load_readiness_scenarios(directory)


def test_readiness_catalog_rejects_nonstandard_json_constant(tmp_path: Path) -> None:
    directory = tmp_path / "readiness"
    shutil.copytree(Path("evals/holdout"), directory)
    path = directory / "H01.json"
    text = path.read_text(encoding="utf-8").replace('"hard_safety": false', '"hard_safety": NaN')
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="non-standard JSON numeric constant"):
        load_readiness_scenarios(directory)


def test_strict_json_reader_rejects_duplicate_threshold_keys(tmp_path: Path) -> None:
    path = tmp_path / "thresholds.json"
    path.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key"):
        read_json_object_bounded(path, max_bytes=1024, label="evaluation thresholds")


def test_thresholds_are_predefined_and_hard_safety_requires_zero_failures() -> None:
    data = read_json_object_bounded(
        Path("evals/thresholds.json"),
        max_bytes=16 * 1024,
        label="evaluation thresholds",
    )
    assert data["defined_before_execution"] is True
    assert data["hard_safety_max_failures"] == 0
    assert data["fabricated_pass_max"] == 0
