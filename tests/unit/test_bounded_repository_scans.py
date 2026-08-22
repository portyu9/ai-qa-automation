from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.intelligence.repository_profile import RepositoryProfiler
from ai_qa_automation.runtime.bootstrap import _dependency_inventory
from ai_qa_automation.runtime.internal_tools import _coverage_search


def test_repository_profiler_stops_at_file_work_bound(tmp_path: Path) -> None:
    for name in ("a.py", "b.py", "c.py"):
        (tmp_path / name).write_text("value = 1\n", encoding="utf-8")

    result = RepositoryProfiler().profile(tmp_path, max_files=2)

    assert result.scanned_files == 2
    assert result.truncated is True


def test_dependency_inventory_reports_scan_truncation(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("irrelevant\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")

    rows, truncated = _dependency_inventory(tmp_path, max_files=100, max_scan_files=1)

    assert rows == []
    assert truncated is True


def test_dependency_inventory_refuses_to_hash_oversized_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "package-lock.json"
    manifest.write_bytes(b"x" * 17)

    rows, truncated = _dependency_inventory(tmp_path, max_file_bytes=16)

    assert truncated is True
    assert rows == [
        {
            "path": "package-lock.json",
            "size": 17,
            "sha256": None,
            "hashed": False,
            "reason": "file-size-limit:16",
        }
    ]


@pytest.mark.parametrize(
    ("name", "kwargs"),
    [
        ("max_files", {"max_files": True}),
        ("max_scan_files", {"max_scan_files": 0}),
        ("max_file_bytes", {"max_file_bytes": 1.5}),
    ],
)
def test_dependency_inventory_rejects_invalid_bounds(
    tmp_path: Path, name: str, kwargs: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match=name):
        _dependency_inventory(tmp_path, **kwargs)  # type: ignore[arg-type]


def test_coverage_search_fails_closed_when_scan_budget_is_exhausted(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("irrelevant\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_checkout.py").write_text(
        "def test_checkout():\n    assert True\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="bounded scan limit"):
        _coverage_search(
            tmp_path,
            query="not-present",
            max_results=10,
            max_scan_files=1,
        )


def test_coverage_search_result_cap_returns_deterministically_before_scan_exhaustion(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("test_a.py", "test_b.py", "test_c.py"):
        (tests / name).write_text("def test_case():\n    assert True\n", encoding="utf-8")

    rows = _coverage_search(tmp_path, query="", max_results=2, max_scan_files=10)

    assert [row["path"] for row in rows] == ["tests/test_a.py", "tests/test_b.py"]
