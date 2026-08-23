from __future__ import annotations

from pathlib import Path
from typing import Never

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.tools.repository import RepositoryInspector


def test_workspace_fingerprint_fails_closed_when_opened_subject_ownership_is_ambiguous(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "tests" / "test_subject.py"
    target.parent.mkdir()
    target.write_text("def test_subject():\n    assert True\n", encoding="utf-8")

    def reject_ambiguous_open(_path: Path, *, label: str) -> Never:
        raise ValueError(f"{label} changed identity during bounded ingestion")

    monkeypatch.setattr(repository_module, "open_regular_binary", reject_ambiguous_open)
    _digest, complete, reasons = RepositoryInspector(tmp_path)._fingerprint(
        "a" * 40,
        " M tests/test_subject.py",
        ("tests/test_subject.py",),
    )

    assert complete is False
    assert "changed-path-ownership-ambiguous" in reasons
