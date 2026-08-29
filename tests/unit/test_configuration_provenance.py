from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.agent import configuration_fingerprint
from ai_qa_automation.config import Settings


def test_base_ref_is_loaded_and_canonicalized_as_trusted_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_BASE_REF", "  origin/main  ")

    settings = Settings(control_root=tmp_path)

    assert settings.base_ref == "origin/main"


def test_explicit_base_ref_has_normal_settings_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_BASE_REF", "origin/main")

    settings = Settings(control_root=tmp_path, base_ref="release/1.x")

    assert settings.base_ref == "release/1.x"


def test_configuration_fingerprint_changes_with_repository_baseline(tmp_path: Path) -> None:
    main = Settings(control_root=tmp_path, base_ref="origin/main")
    release = Settings(control_root=tmp_path, base_ref="release/1.x")

    assert configuration_fingerprint(main) != configuration_fingerprint(release)


def test_blank_base_ref_has_same_runtime_and_provenance_semantics_as_missing(
    tmp_path: Path,
) -> None:
    blank = Settings(control_root=tmp_path, base_ref="   ")
    missing = Settings(control_root=tmp_path, base_ref=None)

    assert blank.base_ref is None
    assert configuration_fingerprint(blank) == configuration_fingerprint(missing)
