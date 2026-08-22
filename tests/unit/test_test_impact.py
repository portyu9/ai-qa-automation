from __future__ import annotations

from pathlib import Path

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
