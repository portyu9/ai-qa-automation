from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
)
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


def test_fingerprint_root_disappearance_is_not_reported_as_file_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")

    workspace = tmp_path / "workspace"
    moved = tmp_path / "authorized-workspace"
    workspace.mkdir()
    (workspace / "tracked.txt").write_text("authorized\n", encoding="utf-8")
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    real_read = repository_module.read_bytes_confined
    moved_once = False

    def remove_root_then_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        nonlocal moved_once
        if not moved_once:
            workspace.rename(moved)
            moved_once = True
        return real_read(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    monkeypatch.setattr(repository_module, "read_bytes_confined", remove_root_then_read)

    with pytest.raises(RepositorySubjectError, match="subject could not be revalidated"):
        inspector._fingerprint(
            "a" * 40,
            " M tracked.txt",
            ("tracked.txt",),
        )

    assert moved_once is True
