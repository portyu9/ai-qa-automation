from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.runtime.model_source_observation import (
    read_model_source_confined,
    search_test_coverage_confined,
)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_confined_model_read_returns_exact_digest_and_root_identity(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    write(target / "tests" / "test_api.py", "def test_api():\n    assert 2 + 2 == 4\n")
    identity = pin_directory_identity(target, label="test workspace")

    observed = read_model_source_confined(
        target,
        "tests/test_api.py",
        expected_root_identity=identity,
    )

    assert observed.text.startswith("def test_api")
    assert observed.size_bytes == len(observed.text.encode("utf-8"))
    assert len(observed.sha256) == 64
    assert observed.root_identity == identity


def test_confined_model_read_rejects_relative_escape(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    target.mkdir()

    with pytest.raises(ValueError, match="relative file path"):
        read_model_source_confined(target, "../outside.py")


def test_confined_model_read_rejects_symlinked_final_file(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    target = tmp_path / "workspace"
    target.mkdir()
    outside = tmp_path / "outside.py"
    write(outside, "OUTSIDE_MARKER = 'must not be read'\n")
    tests = target / "tests"
    tests.mkdir()
    (tests / "test_external.py").symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        read_model_source_confined(target, "tests/test_external.py")


def test_confined_model_read_rejects_symlinked_parent(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    target = tmp_path / "workspace"
    target.mkdir()
    outside = tmp_path / "outside"
    write(outside / "test_external.py", "OUTSIDE_MARKER = 'must not be read'\n")
    (target / "tests").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked parent"):
        read_model_source_confined(target, "tests/test_external.py")


def test_confined_model_read_is_bound_to_expected_workspace_identity(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    write(target / "tests" / "test_old.py", "OLD = True\n")
    identity = pin_directory_identity(target, label="test workspace")
    original = tmp_path / "original"
    target.rename(original)
    write(target / "tests" / "test_old.py", "REPLACEMENT = True\n")

    with pytest.raises(ValueError, match="root changed identity"):
        read_model_source_confined(
            target,
            "tests/test_old.py",
            expected_root_identity=identity,
        )


def test_coverage_search_is_sorted_bounded_and_reports_complete(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    write(target / "tests" / "test_z.py", "def test_login():\n    assert True\n")
    write(target / "tests" / "test_a.py", "def test_login_error():\n    assert True\n")
    write(target / "src" / "app.py", "def login():\n    return True\n")
    identity = pin_directory_identity(target, label="test workspace")

    observed = search_test_coverage_confined(
        target,
        query="login",
        expected_root_identity=identity,
    )

    assert observed.complete is True
    assert observed.incomplete_reasons == ()
    assert [item.path for item in observed.results] == [
        "tests/test_a.py",
        "tests/test_z.py",
    ]
    assert all(item.matches for item in observed.results)
    assert observed.root_identity == identity
    assert observed.observed_source_bytes > 0


def test_coverage_structured_data_sanitizes_discovered_sensitive_path(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    synthetic_fragment = "gh" + "p_" + ("B" * 20)
    synthetic_path = f"tests/test_{synthetic_fragment}.py"
    write(target / synthetic_path, "def test_case():\n    assert True\n")

    observed = search_test_coverage_confined(target, query="")
    structured = observed.as_structured_data(query="")
    rendered = json.dumps(structured)

    assert synthetic_fragment not in rendered
    assert structured["results"][0]["path"] == "tests/test_[REDACTED].py"


def test_coverage_search_result_cap_is_explicitly_incomplete(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    for index in range(3):
        write(target / "tests" / f"test_{index}.py", "def test_case():\n    assert True\n")

    observed = search_test_coverage_confined(target, query="", max_results=2)

    assert [item.path for item in observed.results] == [
        "tests/test_0.py",
        "tests/test_1.py",
    ]
    assert observed.complete is False
    assert "result_limit_reached" in observed.incomplete_reasons


def test_coverage_search_never_descends_symlink_and_marks_namespace_incomplete(
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    target = tmp_path / "workspace"
    target.mkdir()
    outside = tmp_path / "outside"
    write(outside / "tests" / "test_hidden.py", "def test_hidden():\n    assert 'hidden'\n")
    (target / "external-tests").symlink_to(outside, target_is_directory=True)
    write(target / "tests" / "test_safe.py", "def test_safe():\n    assert True\n")

    observed = search_test_coverage_confined(target, query="")

    assert [item.path for item in observed.results] == ["tests/test_safe.py"]
    assert observed.complete is False
    assert observed.unsafe_path_count == 1
    assert "unsafe_or_special_paths_skipped" in observed.incomplete_reasons


def test_coverage_search_invalid_utf8_is_not_silently_treated_as_complete(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    bad = target / "tests" / "test_bad.py"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"\xff\xfe\xfd")
    write(target / "tests" / "test_good.py", "def test_token():\n    assert True\n")

    observed = search_test_coverage_confined(target, query="token")

    assert [item.path for item in observed.results] == ["tests/test_good.py"]
    assert observed.complete is False
    assert observed.skipped_source_count == 1
    assert observed.skipped_source_paths == ("tests/test_bad.py",)
    assert "coverage_source_read_incomplete" in observed.incomplete_reasons


def test_coverage_search_entry_budget_is_explicitly_incomplete(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    for index in range(6):
        write(target / "tests" / f"test_{index}.py", "def test_case():\n    assert True\n")

    observed = search_test_coverage_confined(
        target,
        query="",
        max_scan_entries=2,
    )

    assert observed.complete is False
    assert observed.observed_entries == 2
    assert "filesystem_scan_incomplete" in observed.incomplete_reasons


def test_coverage_search_source_byte_budget_is_enforced_during_ingestion(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    write(target / "tests" / "test_a.py", "token = '" + ("a" * 100) + "'\n")
    write(target / "tests" / "test_b.py", "token = '" + ("b" * 100) + "'\n")

    observed = search_test_coverage_confined(
        target,
        query="token",
        max_source_bytes=120,
    )

    assert observed.complete is False
    assert observed.observed_source_bytes <= 120
    assert "coverage_source_read_incomplete" in observed.incomplete_reasons


def test_coverage_search_rejects_replaced_workspace_root(tmp_path: Path) -> None:
    target = tmp_path / "workspace"
    write(target / "tests" / "test_original.py", "def test_original():\n    assert True\n")
    identity = pin_directory_identity(target, label="test workspace")
    target.rename(tmp_path / "original")
    write(target / "tests" / "test_replacement.py", "def test_replacement():\n    assert True\n")

    with pytest.raises(ValueError, match="root changed identity"):
        search_test_coverage_confined(
            target,
            query="",
            expected_root_identity=identity,
        )
