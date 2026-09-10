from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import (
    bind_pending_root_authority,
    clear_pending_root_authority,
    descriptor_relative_authority_supported,
    pending_root_authority,
)
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector

_SUCCESSOR_LEASE_ID = "lease-new"


def _git(workspace: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=workspace,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


def _workspace_fingerprint(workspace: Path) -> str:
    snapshot = RepositoryInspector(workspace).snapshot()
    assert snapshot.fingerprint_complete is True
    return snapshot.fingerprint


def _strict_recovery_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, bytes, str, tuple[int, int], dict[str, object]]:
    if not descriptor_relative_authority_supported():
        pytest.skip("process-local pending root authority requires descriptor-relative support")

    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    relative_path = Path("tests/test_checkout.py")
    target = workspace / relative_path
    target.parent.mkdir(parents=True)
    original = b"original\n"
    candidate = b"candidate\n"
    target.write_bytes(original)

    _git(workspace, "init", "-q")
    _git(workspace, "add", "--", relative_path.as_posix())
    _git(
        workspace,
        "-c",
        "user.name=QA Fixture",
        "-c",
        "user.email=qa-fixture@example.invalid",
        "commit",
        "-q",
        "-m",
        "fixture baseline",
    )
    pre_fingerprint = _workspace_fingerprint(workspace)
    target.write_bytes(candidate)
    candidate_fingerprint = _workspace_fingerprint(workspace)

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(original)
    workspace_status = workspace.stat(follow_symlinks=False)
    run_status = prior_run.stat(follow_symlinks=False)

    prior = WorkspaceLease(
        artifact_root,
        workspace,
        "run-old",
        run_root_identity=(run_status.st_dev, run_status.st_ino),
    ).acquire()
    prior_lease_id = prior.lease_id
    lease_path = prior.path
    prior.release()
    previous_lease = json.loads(lease_path.read_text(encoding="utf-8"))

    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    runtime = {
        "lease_id": prior_lease_id,
        "workspace": str(workspace.resolve()),
        "workspace_root_identity": {
            "device": workspace_status.st_dev,
            "inode": workspace_status.st_ino,
        },
        "workspace_fingerprint": candidate_fingerprint,
        "journal_event_count": journal.event_count,
        "journal_head_hash": journal.head_hash,
        "pending_mutation": {
            "relative_path": relative_path.as_posix(),
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "change_revision_before": 0,
            "candidate_required": True,
            "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
            "candidate_workspace_fingerprint": candidate_fingerprint,
            "pre_mutation_workspace_fingerprint": pre_fingerprint,
        },
    }
    (prior_run / "runtime.json").write_text(
        json.dumps(runtime, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    StateStore(prior_run / "state.json").save(
        AgentRunState(
            run_id="run-old",
            objective="same-process stale recovery fixture",
            workspace=str(workspace.resolve()),
        )
    )
    workspace_identity = (workspace_status.st_dev, workspace_status.st_ino)
    return (
        artifact_root,
        workspace,
        target,
        original,
        candidate_fingerprint,
        workspace_identity,
        previous_lease,
    )


def _recover(
    artifact_root: Path,
    workspace: Path,
    candidate_fingerprint: str,
    previous_lease: dict[str, object],
) -> dict[str, object]:
    successor = WorkspaceLease(artifact_root, workspace, "run-new").acquire(publish=False)
    try:
        assert successor.previous_metadata == previous_lease
        return recover_stale_mutation(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            current_workspace_fingerprint=candidate_fingerprint,
            recovering_run_id="run-new",
            recovery_lease=successor,
        )
    finally:
        successor.release()


def test_stale_recovery_releases_exact_prior_process_local_root_owner(tmp_path: Path) -> None:
    (
        artifact_root,
        workspace,
        target,
        original,
        candidate_fingerprint,
        workspace_identity,
        previous_lease,
    ) = _strict_recovery_fixture(tmp_path)
    prior_lease_id = str(previous_lease["lease_id"])
    bind_pending_root_authority(workspace, workspace_identity, owner=prior_lease_id)

    result = _recover(artifact_root, workspace, candidate_fingerprint, previous_lease)

    assert result["status"] == "RECOVERED"
    assert target.read_bytes() == original
    assert pending_root_authority(workspace) is None

    bind_pending_root_authority(workspace, workspace_identity, owner=_SUCCESSOR_LEASE_ID)
    assert pending_root_authority(workspace) == workspace_identity
    assert clear_pending_root_authority(
        workspace,
        workspace_identity,
        owner=_SUCCESSOR_LEASE_ID,
    )


def test_stale_recovery_blocks_when_process_local_root_owner_is_not_prior_lease(
    tmp_path: Path,
) -> None:
    (
        artifact_root,
        workspace,
        target,
        original,
        candidate_fingerprint,
        workspace_identity,
        previous_lease,
    ) = _strict_recovery_fixture(tmp_path)
    conflicting_owner = "lease-unrelated"
    bind_pending_root_authority(workspace, workspace_identity, owner=conflicting_owner)

    try:
        result = _recover(artifact_root, workspace, candidate_fingerprint, previous_lease)

        assert result["status"] == "BLOCKED"
        assert "process-local pending root authority" in str(result["reason"])
        assert target.read_bytes() == original
        assert pending_root_authority(workspace) == workspace_identity
        metadata = json.loads(
            (artifact_root / "run-old" / "runtime.json").read_text(encoding="utf-8")
        )
        assert metadata["pending_mutation"] is None

        retry = _recover(artifact_root, workspace, candidate_fingerprint, previous_lease)
        assert retry["status"] == "BLOCKED"
        assert "process-local pending root authority" in str(retry["reason"])
        assert target.read_bytes() == original
        assert pending_root_authority(workspace) == workspace_identity
    finally:
        assert clear_pending_root_authority(
            workspace,
            workspace_identity,
            owner=conflicting_owner,
        )
