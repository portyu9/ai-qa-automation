from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.intelligence.codeowners as codeowners_module
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


def test_codeowners_whole_root_swap_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    codeowners = workspace / ".github" / "CODEOWNERS"
    codeowners.parent.mkdir(parents=True)
    codeowners.write_text("* @inside\n", encoding="utf-8")
    real_read = codeowners_module.read_bytes_confined
    swapped = False

    def replace_root_then_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            swapped = True
            workspace.rename(tmp_path / "workspace-original")
            replacement = workspace / ".github" / "CODEOWNERS"
            replacement.parent.mkdir(parents=True)
            replacement.write_text("* @outside\n", encoding="utf-8")
        return real_read(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    monkeypatch.setattr(codeowners_module, "read_bytes_confined", replace_root_then_read)

    with pytest.raises(ValueError, match="trusted root changed identity"):
        CodeownersResolver.from_workspace(workspace)


def test_unsafe_higher_priority_codeowners_does_not_fall_back(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("* @outside\n", encoding="utf-8")
    preferred = tmp_path / ".github" / "CODEOWNERS"
    preferred.parent.mkdir(parents=True)
    try:
        preferred.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")
    (tmp_path / "CODEOWNERS").write_text("* @fallback\n", encoding="utf-8")

    result = CodeownersResolver.from_workspace(tmp_path).resolve(["src/app.py"])

    assert result.source_path == ".github/CODEOWNERS"
    assert result.ownership_by_file == {}
    assert result.unsupported_patterns == ("<unsafe-or-too-large>",)
