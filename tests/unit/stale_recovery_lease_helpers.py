from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease


def publish_predecessor_lease(
    artifact_root: Path,
    workspace: Path,
    *,
    run_id: str,
    run_root_identity: tuple[int, int],
    lease_id: str | None = None,
) -> dict[str, Any]:
    """Publish and release a real predecessor lease for recovery fixtures."""

    predecessor = WorkspaceLease(
        artifact_root,
        workspace,
        run_id,
        run_root_identity=run_root_identity,
    )
    if lease_id is not None:
        predecessor.lease_id = lease_id
    predecessor.acquire()
    lease_path = predecessor.path
    predecessor.release()
    previous_lease = json.loads(lease_path.read_text(encoding="utf-8"))
    assert previous_lease["run_id"] == run_id
    assert previous_lease["lease_id"] == predecessor.lease_id
    return previous_lease


def recover_with_deferred_successor(
    *,
    artifact_root: Path,
    workspace: Path,
    previous_lease: dict[str, Any],
    current_workspace_fingerprint: str,
    recovering_run_id: str,
    current_workspace_fingerprint_complete: bool = True,
    current_workspace_fingerprint_reasons: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Run stale recovery under the same deferred-successor handoff used by production."""

    successor = WorkspaceLease(artifact_root, workspace, recovering_run_id).acquire(publish=False)
    try:
        assert successor.previous_metadata == previous_lease
        return recover_stale_mutation(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=previous_lease,
            current_workspace_fingerprint=current_workspace_fingerprint,
            recovering_run_id=recovering_run_id,
            current_workspace_fingerprint_complete=current_workspace_fingerprint_complete,
            current_workspace_fingerprint_reasons=current_workspace_fingerprint_reasons,
            recovery_lease=successor,
        )
    finally:
        successor.release()
