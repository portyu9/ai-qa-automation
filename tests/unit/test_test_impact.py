from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.intelligence.test_impact as test_impact_module
from ai_qa_automation.fs_observation import scan_regular_files_confined
from ai_qa_automation.intelligence.test_impact import TestImpactMapper


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_no_changed_files_produces_low_confidence_empty_map(tmp_path: Path) -> None:
    result = TestImpactMapper().map(tmp_path, [])

    assert result.changed_files == ()
    assert result.scanned_test_files == 0
    assert result.candidates == ()
    assert result.scan_truncated is False
    assert result.confidence == 0.2


def test_exact_changed_path_reference_is_ranked_highest(tmp_path: Path) -> None:
    write(
        tmp_path / "tests" / "test_checkout.py",
        "from src.payments.checkout import place_order  # src/payments/checkout.py\n\ndef test_checkout():\n    assert place_order\n",
    )
    write(
        tmp_path / "tests" / "test_profile.py",
        "def test_profile():\n    assert True\n",
    )

    result = TestImpactMapper().map(tmp_path, ["src/payments/checkout.py"])

    assert result.scanned_test_files == 2
    assert result.scan_truncated is False
    assert result.candidates
    top = result.candidates[0]
    assert top.path == "tests/test_checkout.py"
    assert top.score == 0.98
    assert "exact_changed_path_reference" in top.signals
    assert top.matched_changes == ("src/payments/checkout.py",)
    assert result.confidence > 0.5


def test_path_overlap_maps_component_without_claiming_omission_safety(tmp_path: Path) -> None:
    write(
        tmp_path / "integration" / "orders" / "test_order_service.py",
        "def test_order_service():\n    assert True\n",
    )

    result = TestImpactMapper().map(tmp_path, ["src/orders/order_service.py"])

    assert result.candidates
    assert result.candidates[0].path == "integration/orders/test_order_service.py"
    assert any(signal.startswith("path_token_overlap:") for signal in result.candidates[0].signals)
    assert "must not be used as proof" in result.rationale


def test_scan_limit_marks_mapping_truncated_and_low_confidence(tmp_path: Path) -> None:
    for index in range(3):
        write(
            tmp_path / "tests" / f"test_checkout_{index}.py",
            "from src.checkout import handler\n\ndef test_value():\n    assert handler\n",
        )

    result = TestImpactMapper().map(
        tmp_path,
        ["src/checkout.py"],
        max_test_files=1,
    )

    assert result.scanned_test_files == 1
    assert result.scan_truncated is True
    assert result.confidence == 0.35


def test_total_entry_work_limit_bounds_non_test_heavy_repository(tmp_path: Path) -> None:
    write(tmp_path / "a.txt", "one\n")
    write(tmp_path / "b.txt", "two\n")
    write(tmp_path / "tests" / "test_checkout.py", "def test_checkout():\n    assert True\n")

    result = TestImpactMapper().map(
        tmp_path,
        ["src/checkout.py"],
        max_scan_files=2,
    )

    assert result.scanned_test_files == 0
    assert result.scan_truncated is True
    assert result.confidence == 0.35


def test_ignored_dependency_tree_is_not_scanned(tmp_path: Path) -> None:
    write(
        tmp_path / "node_modules" / "pkg" / "test_checkout.js",
        "require('src/checkout')\n",
    )
    write(
        tmp_path / "tests" / "test_real.py",
        "def test_real():\n    assert True\n",
    )

    result = TestImpactMapper().map(tmp_path, ["src/checkout.py"])

    assert result.scanned_test_files == 1
    assert all("node_modules" not in candidate.path for candidate in result.candidates)


def test_oversized_test_file_is_path_scored_but_marks_observation_incomplete(
    tmp_path: Path,
) -> None:
    write(tmp_path / "tests" / "test_checkout.py", "x" * 128)

    result = TestImpactMapper().map(
        tmp_path,
        ["src/checkout.py"],
        max_file_bytes=16,
    )

    assert result.scanned_test_files == 1
    assert result.scan_truncated is True
    assert result.confidence == 0.35
    assert result.candidates == ()


def test_invalid_utf8_marks_observation_incomplete_without_source_promotion(tmp_path: Path) -> None:
    path = tmp_path / "tests" / "test_checkout.py"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"src/payments/checkout.py\xff")

    result = TestImpactMapper().map(tmp_path, ["src/payments/checkout.py"])

    assert result.scan_truncated is True
    assert result.confidence == 0.35
    assert result.candidates == ()


def test_parent_swap_to_symlink_cannot_redirect_test_source_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("descriptor-relative no-follow scan is Unix-only")
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    write(workspace / "tests" / "test_checkout.py", "def test_checkout():\n    assert True\n")
    write(outside / "test_checkout.py", "# src/payments/checkout.py\n")

    real_scan = scan_regular_files_confined

    def scan_then_swap(*args: object, **kwargs: object):
        result = real_scan(*args, **kwargs)
        original = workspace / "tests"
        original.rename(workspace / "tests-original")
        (workspace / "tests").symlink_to(outside, target_is_directory=True)
        return result

    monkeypatch.setattr(test_impact_module, "scan_regular_files_confined", scan_then_swap)

    result = TestImpactMapper().map(workspace, ["src/payments/checkout.py"])

    assert result.scan_truncated is True
    assert result.confidence == 0.35
    assert all("exact_changed_path_reference" not in item.signals for item in result.candidates)


def test_workspace_root_swap_after_scan_cannot_redirect_test_source_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("descriptor-relative no-follow scan is Unix-only")
    workspace = tmp_path / "workspace"
    write(workspace / "tests" / "test_checkout.py", "def test_checkout():\n    assert True\n")

    real_scan = scan_regular_files_confined

    def scan_then_replace_root(*args: object, **kwargs: object):
        result = real_scan(*args, **kwargs)
        workspace.rename(tmp_path / "workspace-original")
        write(
            workspace / "tests" / "test_checkout.py",
            "# src/payments/checkout.py\ndef test_checkout():\n    assert True\n",
        )
        return result

    monkeypatch.setattr(test_impact_module, "scan_regular_files_confined", scan_then_replace_root)

    result = TestImpactMapper().map(workspace, ["src/payments/checkout.py"])

    assert result.scan_truncated is True
    assert result.confidence == 0.35
    assert all("exact_changed_path_reference" not in item.signals for item in result.candidates)


def test_symlink_workspace_root_is_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    real = tmp_path / "real"
    write(real / "tests" / "test_checkout.py", "def test_checkout():\n    assert True\n")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="root is a symlink"):
        TestImpactMapper().map(alias, ["src/checkout.py"])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_test_files": 0},
        {"max_file_bytes": 0},
        {"max_candidates": 0},
        {"max_scan_files": 0},
        {"max_test_files": True},
        {"max_file_bytes": 1.5},
    ],
)
def test_invalid_mapper_work_bounds_are_rejected(tmp_path: Path, kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        TestImpactMapper().map(tmp_path, ["src/checkout.py"], **kwargs)  # type: ignore[arg-type]
