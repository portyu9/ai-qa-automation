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

    def reject_ambiguous_read(
        _root: Path,
        _relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> Never:
        del max_bytes, expected_root_identity
        raise ValueError(f"{label} changed identity during bounded ingestion")

    monkeypatch.setattr(repository_module, "read_bytes_confined", reject_ambiguous_read)
    _digest, complete, reasons = RepositoryInspector(tmp_path)._fingerprint(
        "a" * 40,
        " M tests/test_subject.py",
        ("tests/test_subject.py",),
    )

    assert complete is False
    assert "changed-path-ownership-ambiguous" in reasons
