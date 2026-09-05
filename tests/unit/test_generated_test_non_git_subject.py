from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.runtime.generated_test_authority import (
    GeneratedTestAuthorityError,
    capture_generated_test_repository_subject,
)
from ai_qa_automation.tools.repository import RepositoryInspector


def test_non_git_workspace_content_changes_subject(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    test_file = workspace / "test_subject.py"
    test_file.write_text("value = 1\n", encoding="utf-8")

    before = capture_generated_test_repository_subject(
        workspace,
        expected_root_identity=None,
        change_revision=0,
    )
    test_file.write_text("value = 2\n", encoding="utf-8")
    after = capture_generated_test_repository_subject(
        workspace,
        expected_root_identity=None,
        change_revision=0,
    )

    assert before.git_sha is None
    assert after.git_sha is None
    assert before.workspace_root_identity == after.workspace_root_identity
    assert before.workspace_fingerprint != after.workspace_fingerprint


def test_non_git_workspace_root_replacement_after_inspector_pin_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "test_subject.py").write_text("value = 1\n", encoding="utf-8")
    moved_workspace = tmp_path / "original-workspace"
    original_snapshot = RepositoryInspector.snapshot
    replaced = False

    def snapshot_then_replace_root(self: RepositoryInspector):
        nonlocal replaced
        snapshot = original_snapshot(self)
        if self.workspace == workspace and not replaced:
            workspace.rename(moved_workspace)
            workspace.mkdir()
            (workspace / "replacement.py").write_text("value = 2\n", encoding="utf-8")
            replaced = True
        return snapshot

    monkeypatch.setattr(RepositoryInspector, "snapshot", snapshot_then_replace_root)

    with pytest.raises(
        GeneratedTestAuthorityError,
        match="non-Git workspace namespace could not be observed",
    ):
        capture_generated_test_repository_subject(
            workspace,
            expected_root_identity=None,
            change_revision=0,
        )

    assert replaced is True
