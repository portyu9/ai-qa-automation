from pathlib import Path

from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.tools.safe_patch import SafeTestPatcher


def test_safe_patcher_uses_hash_and_preserves_valid_python(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    file = tmp_path / "tests" / "test_ui.py"
    file.write_text("def test_button():\n    assert locate('#old')\n")
    policy = PolicyEngine(tmp_path, tmp_path, allow_test_writes=True)
    patcher = SafeTestPatcher(tmp_path, policy)
    digest = patcher.sha256_text(file.read_text())
    result = patcher.replace_once(
        relative_path="tests/test_ui.py",
        expected_sha256=digest,
        old_text="locate('#old')",
        new_text="locate('[data-testid=save]')",
    )
    assert result.old_sha256 == digest
    assert "data-testid" in file.read_text()


def test_safe_patcher_rejects_stale_or_intent_eroding_patch(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    file = tmp_path / "tests" / "test_ui.py"
    file.write_text("def test_button():\n    assert True\n")
    policy = PolicyEngine(tmp_path, tmp_path, allow_test_writes=True)
    patcher = SafeTestPatcher(tmp_path, policy)
    try:
        patcher.replace_once(relative_path="tests/test_ui.py", expected_sha256="stale", old_text="assert True", new_text="pass")
    except RuntimeError:
        pass
    else:
        raise AssertionError("stale optimistic-concurrency hash must block patch")


def test_generated_test_must_have_meaningful_assertion(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    patcher = SafeTestPatcher(tmp_path, PolicyEngine(tmp_path, tmp_path, allow_test_writes=True))
    try:
        patcher.create_test(relative_path="tests/test_generated.py", content="def test_empty():\n    value = 1\n")
    except PermissionError:
        pass
    else:
        raise AssertionError("assertionless generated test must be blocked")


def test_generated_asserting_test_can_be_created(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    patcher = SafeTestPatcher(tmp_path, PolicyEngine(tmp_path, tmp_path, allow_test_writes=True))
    result = patcher.create_test(relative_path="tests/test_generated.py", content="def test_math():\n    assert 2 + 2 == 4\n")
    assert result.old_sha256 == "ABSENT"
    assert (tmp_path / "tests/test_generated.py").is_file()
