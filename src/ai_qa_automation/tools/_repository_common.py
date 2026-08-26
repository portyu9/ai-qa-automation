from __future__ import annotations

import re
from dataclasses import dataclass

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_GIT_MODE = re.compile(r"^[0-7]{6}$")
_GIT_GRAFT_WARNING = "info/grafts"
_MAX_FINGERPRINT_CHANGED_FILES = 1000
_MAX_FINGERPRINT_FILE_BYTES = 16_000_000
_MAX_FINGERPRINT_TOTAL_BYTES = 128_000_000
_MAX_GIT_TEXT_OUTPUT_BYTES = 8_000_000
_MAX_GIT_EXACT_STDOUT_BYTES = 16_000_000
_MAX_GIT_EXACT_STDERR_BYTES = 256_000
_MAX_GIT_INDEX_BYTES = 16_000_000
_MAX_GIT_PATHS = 100_000
_MAX_GIT_METADATA_SCAN_ENTRIES = 100_000
_MAX_GIT_CONFIG_BYTES = 256_000


def raise_if_git_grafts_reported(stderr: str) -> None:
    if _GIT_GRAFT_WARNING in stderr.casefold():
        raise RuntimeError("Git graft metadata is not permitted during repository inspection")


class RepositorySubjectError(RuntimeError):
    """Raised when Git inspection cannot remain bound to the authorized workspace subject."""


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]
    fingerprint: str
    fingerprint_complete: bool
    fingerprint_incomplete_reasons: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryChangeSet:
    """Diff-aware change set anchored to an explicit trusted baseline ref."""

    requested_base_ref: str
    baseline_sha: str
    merge_base_sha: str
    head_sha: str
    committed_files: tuple[str, ...]
    worktree_files: tuple[str, ...]
    changed_files: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "requested_base_ref": self.requested_base_ref,
            "baseline_sha": self.baseline_sha,
            "merge_base_sha": self.merge_base_sha,
            "head_sha": self.head_sha,
            "committed_files": list(self.committed_files),
            "worktree_files": list(self.worktree_files),
            "changed_files": list(self.changed_files),
        }
