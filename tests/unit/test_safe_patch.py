from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.safe_patch import SafeTestPatcher


def make_patcher(tmp_path: Path) -> SafeTestPatcher:
    (tmp_path / "tests").mkdir(exist_ok=True)
    return SafeTestPatcher(
        tmp_path,
        PolicyEngine(tmp_path, tmp_path, allow_test_writes=True),
    )


def test_safe_patcher_uses_hash_and_preserves_valid_python(tmp_path: Path) -> None:
    file = tmp_path / "tests" / "test_ui.py"
    (tmp_path / "tests").mkdir()
    file.write_text("def test_button():\n    assert locate('#old')\n", encoding="utf-8")
    patcher = make_patcher(tmp_path)
    digest = patcher.sha256_text(file.read_text(encoding="utf-8"))

    result = patcher.replace_once(
        relative_path="tests/test_ui.py",
        expected_sha256=digest,
        old_text="locate('#old')",
        new_text="locate('[data-testid=save]')",
    )

    assert result.old_sha256 == digest
    assert result.new_sha256 == patcher.sha256_text(file.read_text(encoding="utf-8"))
    assert result.old_sha256 != result.new_sha256
    assert "data-testid" in file.read_text(encoding="utf-8")
    assert "--- a/tests/test_ui.py" in result.diff
    assert "+++ b/tests/test_ui.py" in result.diff


def test_stale_hash_blocks_patch_and_leaves_original_bytes_untouched(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    file = tmp_path / "tests" / "test_ui.py"
    original = "def test_button():\n    assert locate('#old')\n"
    file.write_text(original, encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed since proposal"):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256="stale",
            old_text="locate('#old')",
            new_text="locate('#new')",
        )

    assert file.read_text(encoding="utf-8") == original


def test_old_text_must_match_exactly_once_and_ambiguous_patch_is_non_mutating(
    tmp_path: Path,
) -> None:
    patcher = make_patcher(tmp_path)
    file = tmp_path / "tests" / "test_ui.py"
    original = "def test_button():\n    assert locate('#old')\n    assert locate('#old')\n"
    file.write_text(original, encoding="utf-8")
    digest = patcher.sha256_text(original)

    with pytest.raises(ValueError, match="exactly once"):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256=digest,
            old_text="locate('#old')",
            new_text="locate('#new')",
        )

    assert file.read_text(encoding="utf-8") == original


def test_assertion_removal_is_blocked_even_if_resulting_python_is_valid(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    file = tmp_path / "tests" / "test_ui.py"
    original = "def test_button():\n    assert response.status_code == 200\n"
    file.write_text(original, encoding="utf-8")

    with pytest.raises(PermissionError):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256=patcher.sha256_text(original),
            old_text="assert response.status_code == 200",
            new_text="response.status_code",
        )

    assert file.read_text(encoding="utf-8") == original


def test_invalid_python_patch_is_rejected_before_atomic_replace(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    file = tmp_path / "tests" / "test_ui.py"
    original = "def test_button():\n    assert True\n"
    file.write_text(original, encoding="utf-8")

    with pytest.raises(SyntaxError):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256=patcher.sha256_text(original),
            old_text="assert True",
            new_text="assert (",
        )

    assert file.read_text(encoding="utf-8") == original


def test_locator_replacement_accepts_only_supported_literal_locator_expressions(
    tmp_path: Path,
) -> None:
    patcher = make_patcher(tmp_path)
    file = tmp_path / "tests" / "test_ui.py"
    original = (
        "def test_button(page):\n"
        "    assert page.get_by_test_id('old').is_visible()\n"
    )
    file.write_text(original, encoding="utf-8")
    digest = patcher.sha256_text(original)

    result = patcher.replace_locator_once(
        relative_path="tests/test_ui.py",
        expected_sha256=digest,
        old_locator="page.get_by_test_id('old')",
        new_locator="page.get_by_role('button', name='Save')",
    )
    assert "get_by_role" in file.read_text(encoding="utf-8")
    assert result.old_sha256 == digest

    updated = file.read_text(encoding="utf-8")
    with pytest.raises(PermissionError, match="supported literal locator"):
        patcher.replace_locator_once(
            relative_path="tests/test_ui.py",
            expected_sha256=patcher.sha256_text(updated),
            old_locator="page.get_by_role('button', name='Save')",
            new_locator="page.locator(dynamic_selector)",
        )


def test_locator_replacement_rejects_noop(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    with pytest.raises(ValueError, match="must differ"):
        patcher.replace_locator_once(
            relative_path="tests/test_ui.py",
            expected_sha256="unused",
            old_locator="page.get_by_test_id('save')",
            new_locator="page.get_by_test_id('save')",
        )


def test_generated_python_test_must_have_meaningful_assertion(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    with pytest.raises(PermissionError, match="quality review"):
        patcher.create_test(
            relative_path="tests/test_generated.py",
            content="def test_empty():\n    value = 1\n",
        )
    assert not (tmp_path / "tests" / "test_generated.py").exists()


def test_generated_python_tautology_is_rejected(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    with pytest.raises(PermissionError):
        patcher.create_test(
            relative_path="tests/test_generated.py",
            content="def test_fake():\n    assert True\n",
        )


def test_generated_asserting_python_test_can_be_created(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    content = "def test_math():\n    assert 2 + 2 == 4\n"
    result = patcher.create_test(relative_path="tests/test_generated.py", content=content)
    assert result.old_sha256 == "ABSENT"
    assert result.new_sha256 == patcher.sha256_text(content)
    assert (tmp_path / "tests/test_generated.py").read_text(encoding="utf-8") == content


@pytest.mark.parametrize("suffix", ["js", "ts"])
def test_js_ts_assertion_text_inside_comment_or_string_does_not_count(
    tmp_path: Path, suffix: str
) -> None:
    patcher = make_patcher(tmp_path)
    content = (
        "// expect(result).toEqual(expected)\n"
        "const fake = 'expect(value).toBe(true)';\n"
        "const value = 1;\n"
    )

    with pytest.raises(PermissionError, match="no observable assertion"):
        patcher.create_test(
            relative_path=f"tests/generated.{suffix}",
            content=content,
        )


@pytest.mark.parametrize("suffix", ["js", "ts"])
def test_js_ts_real_assertion_is_accepted(tmp_path: Path, suffix: str) -> None:
    patcher = make_patcher(tmp_path)
    content = "test('math', () => { const value = 2 + 2; expect(value).toBe(4); });\n"
    result = patcher.create_test(
        relative_path=f"tests/generated.{suffix}",
        content=content,
    )
    assert result.old_sha256 == "ABSENT"
    assert (tmp_path / "tests" / f"generated.{suffix}").is_file()


def test_generated_file_never_overwrites_existing_test(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    destination = tmp_path / "tests" / "test_existing.py"
    destination.write_text("def test_existing():\n    assert 1 == 1\n", encoding="utf-8")
    original = destination.read_bytes()

    with pytest.raises(FileExistsError):
        patcher.create_test(
            relative_path="tests/test_existing.py",
            content="def test_new():\n    assert 2 == 2\n",
        )

    assert destination.read_bytes() == original


def test_unsupported_generated_extension_is_denied(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    with pytest.raises(PermissionError, match="Python/JavaScript/TypeScript"):
        patcher.create_test(
            relative_path="tests/test_generated.rb",
            content="raise unless 2 + 2 == 4\n",
        )


def test_generated_test_cannot_escape_approved_test_directories(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    with pytest.raises(PermissionError):
        patcher.create_test(
            relative_path="src/test_generated.py",
            content="def test_math():\n    assert 2 + 2 == 4\n",
        )


def test_generated_test_size_limit_is_checked_before_write(tmp_path: Path) -> None:
    patcher = make_patcher(tmp_path)
    content = "#" * 1_000_001
    with pytest.raises(ValueError, match="byte limit"):
        patcher.create_test(relative_path="tests/test_large.py", content=content)
    assert not (tmp_path / "tests" / "test_large.py").exists()
