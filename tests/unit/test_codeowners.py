from __future__ import annotations

from pathlib import Path

from ai_qa_automation.intelligence.codeowners import CodeownersResolver


def test_missing_codeowners_reports_files_as_unowned(tmp_path: Path) -> None:
    resolver = CodeownersResolver.from_workspace(tmp_path)
    result = resolver.resolve(["src/app.py", "tests/test_app.py"])

    assert result.source_path is None
    assert result.ownership_by_file == {}
    assert result.unowned_files == ("src/app.py", "tests/test_app.py")
    assert result.unsupported_patterns == ()


def test_codeowners_uses_last_matching_rule(tmp_path: Path) -> None:
    codeowners = tmp_path / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text(
        "* @all\n/src/** @backend\n/src/security/** @security\n",
        encoding="utf-8",
    )

    resolver = CodeownersResolver.from_workspace(tmp_path)
    result = resolver.resolve(["src/service.py", "src/security/auth.py", "README.md"])

    assert result.source_path == ".github/CODEOWNERS"
    assert result.ownership_by_file["src/service.py"] == ("@backend",)
    assert result.ownership_by_file["src/security/auth.py"] == ("@security",)
    assert result.ownership_by_file["README.md"] == ("@all",)
    assert result.unowned_files == ()


def test_directory_and_question_mark_patterns_are_supported(tmp_path: Path) -> None:
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text(
        "/docs/ @docs\nconfig?.yaml @platform\n",
        encoding="utf-8",
    )

    result = CodeownersResolver.from_workspace(tmp_path).resolve(
        ["docs/runbook/ops.md", "config1.yaml", "nested/configA.yaml"]
    )

    assert result.ownership_by_file["docs/runbook/ops.md"] == ("@docs",)
    assert result.ownership_by_file["config1.yaml"] == ("@platform",)
    assert result.ownership_by_file["nested/configA.yaml"] == ("@platform",)


def test_unsupported_patterns_are_reported_not_guessed(tmp_path: Path) -> None:
    codeowners = tmp_path / "CODEOWNERS"
    codeowners.write_text(
        "!generated/** @nobody\nsrc/[ab].py @team\nsrc/** @backend\n",
        encoding="utf-8",
    )

    resolver = CodeownersResolver.from_workspace(tmp_path)
    result = resolver.resolve(["src/a.py", "generated/file.py"])

    assert result.ownership_by_file["src/a.py"] == ("@backend",)
    assert "generated/file.py" in result.unowned_files
    assert result.unsupported_patterns == (
        "line 1: !generated/**",
        "line 2: src/[ab].py",
    )
