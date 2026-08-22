from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.tools.repository import RepositoryInspector


def test_snapshot_marks_git_inspection_failure_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspector = RepositoryInspector(tmp_path)

    def timeout(*args: str, **kwargs: object) -> str | None:
        raise RuntimeError("git command exceeded inspection budget")

    monkeypatch.setattr(inspector, "_git", timeout)

    snapshot = inspector.snapshot()

    assert snapshot.git_sha is None
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == ("git-inspection-timeout",)
    assert "INCOMPLETE" in snapshot.status


def test_repository_inspection_requires_positive_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        RepositoryInspector(tmp_path, timeout_seconds=0)
