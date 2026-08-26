from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.runtime.bootstrap as bootstrap
from ai_qa_automation.intelligence.repository_profile import RepositoryProfiler
from ai_qa_automation.runtime.bootstrap import _dependency_inventory
from ai_qa_automation.runtime.internal_tools import _coverage_search
from ai_qa_automation.tools.repository import RepositoryChangeSet


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


def _install_final_component_symlink_swap(
    *,
    outside: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_read = bootstrap.read_bytes_confined

    def swap_then_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        path = root / relative_path
        path.unlink()
        try:
            path.symlink_to(outside)
        except OSError as exc:  # pragma: no cover - platform/filesystem capability
            pytest.skip(f"symlink creation unavailable: {exc}")
        return real_read(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    monkeypatch.setattr(bootstrap, "read_bytes_confined", swap_then_read)


def test_dependency_inventory_fails_closed_on_final_component_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project]\nname='owned'\n", encoding="utf-8")
    outside = tmp_path / "outside.toml"
    outside.write_text("[project]\nname='untrusted'\n", encoding="utf-8")
    _install_final_component_symlink_swap(outside=outside, monkeypatch=monkeypatch)

    rows, truncated = bootstrap._dependency_inventory(tmp_path)

    assert truncated is True
    assert rows == [
        {
            "path": "pyproject.toml",
            "size": None,
            "sha256": None,
            "hashed": False,
            "reason": "read-failed-or-grew-during-hash",
        }
    ]


def test_contract_drift_fails_closed_on_final_component_symlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = tmp_path / "openapi.json"
    current.write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text('{"openapi":"3.1.0","paths":{"/evil":{}}}', encoding="utf-8")
    _install_final_component_symlink_swap(outside=outside, monkeypatch=monkeypatch)

    class Inspector:
        @staticmethod
        def read_file_at(_commit_sha: str, _relative_path: str, *, max_bytes: int) -> bytes:
            assert max_bytes == 2_000_000
            return b'{"openapi":"3.1.0","paths":{}}'

    change_set = RepositoryChangeSet(
        requested_base_ref="main",
        baseline_sha="a" * 40,
        merge_base_sha="b" * 40,
        head_sha="c" * 40,
        committed_files=("openapi.json",),
        worktree_files=(),
        changed_files=("openapi.json",),
    )

    reports = bootstrap._contract_drift_reports(
        workspace=tmp_path,
        inspector=Inspector(),  # type: ignore[arg-type]
        change_set=change_set,
        changed_files=("openapi.json",),
    )

    assert reports == [
        {
            "path": "openapi.json",
            "contract_kind": "openapi",
            "severity": "NOT_ANALYZED",
            "changes": [],
            "analyzed": False,
            "reason": "current read failed: ValueError",
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


def test_coverage_search_reports_incomplete_when_scan_budget_is_exhausted(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("irrelevant\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_checkout.py").write_text(
        "def test_checkout():\n    assert True\n", encoding="utf-8"
    )

    observed = _coverage_search(
        tmp_path,
        query="not-present",
        max_results=10,
        max_scan_files=1,
    )

    assert observed.complete is False
    assert "filesystem_scan_incomplete" in observed.incomplete_reasons
    assert observed.observed_entries == 1


def test_coverage_search_result_cap_is_deterministic_and_explicitly_incomplete(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    for name in ("test_a.py", "test_b.py", "test_c.py"):
        (tests / name).write_text("def test_case():\n    assert True\n", encoding="utf-8")

    observed = _coverage_search(tmp_path, query="", max_results=2, max_scan_files=10)

    assert [item.path for item in observed.results] == ["tests/test_a.py", "tests/test_b.py"]
    assert observed.complete is False
    assert "result_limit_reached" in observed.incomplete_reasons
