from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ..tools.repository import RepositoryInspector


class WorkspaceFreshnessCode(StrEnum):
    FRESH = "FRESH"
    BASELINE_MISSING = "BASELINE_MISSING"
    FINGERPRINT_INCOMPLETE = "FINGERPRINT_INCOMPLETE"
    WORKSPACE_DRIFT = "WORKSPACE_DRIFT"
    SUBJECT_UNAVAILABLE = "SUBJECT_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class WorkspaceFreshness:
    code: WorkspaceFreshnessCode
    reason: str

    @property
    def fresh(self) -> bool:
        return self.code is WorkspaceFreshnessCode.FRESH


def observe_workspace_freshness(
    workspace: Path,
    *,
    expected_fingerprint: str | None,
    expected_root_identity: tuple[int, int] | None,
) -> WorkspaceFreshness:
    """Re-prove the current target subject without adopting a newly observed baseline."""

    if expected_fingerprint is None:
        return WorkspaceFreshness(
            WorkspaceFreshnessCode.BASELINE_MISSING,
            "No authorized workspace fingerprint baseline is available for freshness validation.",
        )
    try:
        snapshot = RepositoryInspector(
            workspace,
            expected_root_identity=expected_root_identity,
        ).snapshot()
    except (OSError, RuntimeError, ValueError):
        return WorkspaceFreshness(
            WorkspaceFreshnessCode.SUBJECT_UNAVAILABLE,
            "Workspace subject identity could not be revalidated safely.",
        )
    if not snapshot.fingerprint_complete:
        return WorkspaceFreshness(
            WorkspaceFreshnessCode.FINGERPRINT_INCOMPLETE,
            "Workspace fingerprint observation is incomplete and cannot certify freshness.",
        )
    if snapshot.fingerprint != expected_fingerprint:
        return WorkspaceFreshness(
            WorkspaceFreshnessCode.WORKSPACE_DRIFT,
            "Target workspace changed outside the authorized fingerprint lineage.",
        )
    return WorkspaceFreshness(
        WorkspaceFreshnessCode.FRESH,
        "Current workspace fingerprint matches the authorized runtime baseline.",
    )
