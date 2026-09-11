from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.tools.subprocess_subject import (
    active_workspace_authority,
    bind_active_workspace_authority,
    clear_active_workspace_authority,
)


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace lease interruption tests require descriptor-relative support")


def test_acquire_interruption_after_workspace_lock_releases_inode_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-interrupted-lock")

    real_revalidate = workspace_lease_module.WorkspaceLease._revalidate_workspace_root
    calls = 0

    def interrupt_after_lock(self: WorkspaceLease) -> None:
        nonlocal calls
        calls += 1
        real_revalidate(self)
        if self is lease and calls == 2:
            raise KeyboardInterrupt("simulated interruption after workspace flock")

    with monkeypatch.context() as scoped:
        scoped.setattr(
            workspace_lease_module.WorkspaceLease,
            "_revalidate_workspace_root",
            interrupt_after_lock,
        )
        with pytest.raises(KeyboardInterrupt, match="workspace flock"):
            lease.acquire(publish=False)

    successor = WorkspaceLease(artifacts, workspace, "run-successor")
    successor.acquire(publish=False)
    successor.release()


def test_acquire_interruption_after_process_authority_bind_releases_all_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-interrupted-bind")
    real_bind = workspace_lease_module.bind_active_workspace_authority

    def bind_then_interrupt(
        root: Path,
        identity: tuple[int, int] | None,
        *,
        owner: str,
    ) -> None:
        real_bind(root, identity, owner=owner)
        raise KeyboardInterrupt("simulated interruption after process authority bind")

    with monkeypatch.context() as scoped:
        scoped.setattr(
            workspace_lease_module,
            "bind_active_workspace_authority",
            bind_then_interrupt,
        )
        with pytest.raises(KeyboardInterrupt, match="process authority bind"):
            lease.acquire(publish=False)

    assert active_workspace_authority(workspace) is None
    successor = WorkspaceLease(artifacts, workspace, "run-successor")
    successor.acquire(publish=False)
    successor.release()


def test_acquire_cleanup_retries_exact_authority_clear_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-interrupted-cleanup")
    real_bind = workspace_lease_module.bind_active_workspace_authority
    real_clear = workspace_lease_module.clear_active_workspace_authority
    clear_calls = 0

    def bind_then_interrupt(
        root: Path,
        identity: tuple[int, int] | None,
        *,
        owner: str,
    ) -> None:
        real_bind(root, identity, owner=owner)
        raise KeyboardInterrupt("simulated acquisition interruption")

    def interrupt_first_clear(
        root: Path,
        identity: tuple[int, int] | None,
        *,
        owner: str,
    ) -> bool:
        nonlocal clear_calls
        clear_calls += 1
        if clear_calls == 1:
            raise KeyboardInterrupt("simulated cleanup interruption")
        return real_clear(root, identity, owner=owner)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            workspace_lease_module,
            "bind_active_workspace_authority",
            bind_then_interrupt,
        )
        scoped.setattr(
            workspace_lease_module,
            "clear_active_workspace_authority",
            interrupt_first_clear,
        )
        with pytest.raises(KeyboardInterrupt, match="acquisition interruption"):
            lease.acquire(publish=False)

    assert clear_calls == 2
    assert active_workspace_authority(workspace) is None
    successor = WorkspaceLease(artifacts, workspace, "run-successor")
    successor.acquire(publish=False)
    successor.release()


def test_release_interruption_during_process_authority_clear_still_releases_os_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-interrupted-release").acquire(publish=False)
    real_clear = workspace_lease_module.clear_active_workspace_authority
    interrupted = False

    def clear_then_interrupt(
        root: Path,
        identity: tuple[int, int] | None,
        *,
        owner: str,
    ) -> bool:
        nonlocal interrupted
        result = real_clear(root, identity, owner=owner)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt("simulated interruption during process authority clear")
        return result

    with monkeypatch.context() as scoped:
        scoped.setattr(
            workspace_lease_module,
            "clear_active_workspace_authority",
            clear_then_interrupt,
        )
        with pytest.raises(KeyboardInterrupt, match="process authority clear"):
            lease.release()

    assert active_workspace_authority(workspace) is None
    successor = WorkspaceLease(artifacts, workspace, "run-successor")
    successor.acquire(publish=False)
    successor.release()


def test_release_unlock_interruption_resets_lease_object_and_closes_os_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-reusable").acquire(publish=False)

    def interrupt_unlock(_fd: int) -> None:
        raise KeyboardInterrupt("simulated workspace unlock interruption")

    with monkeypatch.context() as scoped:
        scoped.setattr(
            workspace_lease_module.WorkspaceLease,
            "_unlock_workspace_root",
            staticmethod(interrupt_unlock),
        )
        with pytest.raises(KeyboardInterrupt, match="workspace unlock interruption"):
            lease.release()

    assert active_workspace_authority(workspace) is None
    lease.acquire(publish=False)
    lease.release()


def test_process_authority_conflict_does_not_publish_failed_lease_owner(tmp_path: Path) -> None:
    _require_descriptor_authority()
    artifacts = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    predecessor = WorkspaceLease(artifacts, workspace, "run-predecessor").acquire()
    lease_path = predecessor.path
    predecessor_id = predecessor.lease_id
    predecessor.release()
    predecessor_metadata = json.loads(lease_path.read_text(encoding="utf-8"))
    assert predecessor_metadata["lease_id"] == predecessor_id

    workspace_identity = predecessor.workspace_root_identity
    assert workspace_identity is not None
    foreign_owner = "lease-foreign-owner"
    bind_active_workspace_authority(workspace, workspace_identity, owner=foreign_owner)
    try:
        rejected = WorkspaceLease(artifacts, workspace, "run-rejected")
        with pytest.raises(OSError, match="process-local workspace lease authority conflicts"):
            rejected.acquire()

        durable = json.loads(lease_path.read_text(encoding="utf-8"))
        assert durable == predecessor_metadata
    finally:
        assert clear_active_workspace_authority(
            workspace,
            workspace_identity,
            owner=foreign_owner,
        )

    successor = WorkspaceLease(artifacts, workspace, "run-successor")
    successor.acquire(publish=False)
    successor.release()
