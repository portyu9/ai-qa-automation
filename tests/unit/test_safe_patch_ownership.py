from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.safe_patch import SafeTestPatcher


def patcher(tmp_path: Path) -> SafeTestPatcher:
    return SafeTestPatcher(
        tmp_path,
        PolicyEngine(tmp_path, tmp_path, allow_test_writes=True),
    )


def test_direct_patch_rejects_symlinked_test_directory(tmp_path: Path) -> None:
    actual = tmp_path / "actual-tests"
    actual.mkdir()
    target = actual / "test_checkout.py"
    original = "def test_checkout():\n    assert 1 == 1\n"
    target.write_text(original, encoding="utf-8")
    alias = tmp_path / "tests"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    subject = patcher(tmp_path)
    with pytest.raises(PermissionError, match="symlink"):
        subject.replace_once(
            relative_path="tests/test_checkout.py",
            expected_sha256=subject.sha256_text(original),
            old_text="1 == 1",
            new_text="2 == 2",
        )

    assert target.read_text(encoding="utf-8") == original


def test_direct_create_rejects_symlinked_test_directory(tmp_path: Path) -> None:
    actual = tmp_path / "actual-tests"
    actual.mkdir()
    alias = tmp_path / "tests"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(PermissionError, match="symlink"):
        patcher(tmp_path).create_test(
            relative_path="tests/test_generated.py",
            content="def test_generated():\n    assert 2 + 2 == 4\n",
        )

    assert not (actual / "test_generated.py").exists()


def test_direct_mutation_rejects_parent_traversal_even_when_it_normalizes_inside_workspace(
    tmp_path: Path,
) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    target = tests / "test_checkout.py"
    original = "def test_checkout():\n    assert 1 == 1\n"
    target.write_text(original, encoding="utf-8")
    subject = patcher(tmp_path)

    with pytest.raises(PermissionError, match="non-traversing"):
        subject.replace_once(
            relative_path="tests/../tests/test_checkout.py",
            expected_sha256=subject.sha256_text(original),
            old_text="1 == 1",
            new_text="2 == 2",
        )

    assert target.read_text(encoding="utf-8") == original
