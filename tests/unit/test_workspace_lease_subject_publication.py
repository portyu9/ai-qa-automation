from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.tools.subprocess_subject import active_workspace_authority


def test_workspace_lease_revalidates_root_after_authority_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")

    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    displaced_replacement = tmp_path / "displaced-replacement"
    artifacts = tmp_path / "artifacts"
    workspace.mkdir()
    replacement.mkdir()
    artifacts.mkdir()

    lease = WorkspaceLease(artifacts, workspace, "run-publication-race")
    real_bind = workspace_lease_module.bind_active_workspace_authority

    def bind_then_replace(
        root: Path,
        identity: tuple[int, int] | None,
        *,
        owner: str,
    ) -> None:
        real_bind(root, identity, owner=owner)
        workspace.rename(moved)
        replacement.rename(workspace)

    monkeypatch.setattr(
        workspace_lease_module,
        "bind_active_workspace_authority",
        bind_then_replace,
    )

    with pytest.raises(OSError, match="target workspace"):
        lease.acquire()

    assert active_workspace_authority(workspace) is None

    # Restore the authorized inode at the canonical pathname and prove the failed
    # acquisition released both the workspace lock and the external lease-file lock.
    workspace.rename(displaced_replacement)
    moved.rename(workspace)
    successor = WorkspaceLease(artifacts, workspace, "run-after-publication-race")
    successor.acquire()
    successor.release()
