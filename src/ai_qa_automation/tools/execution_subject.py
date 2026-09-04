from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from ..fs_authority import atomic_write_bytes_confined, pin_directory_identity
from ._repository_common import (
    _MAX_FINGERPRINT_CHANGED_FILES,
    _MAX_FINGERPRINT_FILE_BYTES,
    _MAX_FINGERPRINT_TOTAL_BYTES,
    _MAX_GIT_EXACT_STDOUT_BYTES,
    _MAX_GIT_PATHS,
)
from .repository import RepositoryInspector, RepositorySnapshot

_MAX_EXECUTION_SUBJECT_TOTAL_BYTES = _MAX_FINGERPRINT_TOTAL_BYTES * 2


class ExecutionSubjectError(RuntimeError):
    """Raised when pytest execution bytes cannot be frozen to one repository subject."""


@dataclass(frozen=True)
class MaterializedExecutionSubject:
    root: Path
    root_identity: tuple[int, int]
    git_sha: str
    source_fingerprint: str
    digest: str
    file_count: int
    total_bytes: int
    ignored_inputs_excluded: bool = True
    git_metadata_excluded: bool = True

    def details(self) -> dict[str, object]:
        return {
            "git_sha": self.git_sha,
            "source_fingerprint": self.source_fingerprint,
            "digest": self.digest,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "ignored_inputs_excluded": self.ignored_inputs_excluded,
            "git_metadata_excluded": self.git_metadata_excluded,
        }


def _same_snapshot(left: RepositorySnapshot, right: RepositorySnapshot) -> bool:
    return (
        left.git_sha == right.git_sha
        and left.branch == right.branch
        and left.status == right.status
        and left.changed_files == right.changed_files
        and left.fingerprint == right.fingerprint
        and left.fingerprint_complete == right.fingerprint_complete
        and left.fingerprint_incomplete_reasons == right.fingerprint_incomplete_reasons
    )


def _require_complete_git_snapshot(snapshot: RepositorySnapshot) -> None:
    if snapshot.git_sha is None:
        raise ExecutionSubjectError("pytest execution requires a Git-backed target workspace")
    if not snapshot.fingerprint_complete:
        reasons = ",".join(snapshot.fingerprint_incomplete_reasons)
        suffix = f" ({reasons})" if reasons else ""
        raise ExecutionSubjectError(f"workspace fingerprint is incomplete{suffix}")
    if len(snapshot.changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
        raise ExecutionSubjectError("workspace changed-file subject exceeds its bounded file budget")


def _fingerprint_from_materialized_changed_files(
    snapshot: RepositorySnapshot,
    *,
    index_digest: str,
    copied: dict[str, tuple[int, str]],
) -> str:
    rows: list[dict[str, object]] = []
    for relative in snapshot.changed_files:
        observed = copied.get(relative)
        if observed is None:
            rows.append({"path": relative, "state": "deleted"})
            continue
        size, digest = observed
        rows.append({"path": relative, "size": size, "sha256": digest})
    payload = {
        "git_sha": snapshot.git_sha,
        "status": snapshot.status,
        "index_sha256": index_digest,
        "files": rows,
        "fingerprint_complete": True,
        "fingerprint_incomplete_reasons": [],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


@contextmanager
def materialized_pytest_execution_subject(
    workspace: Path,
    *,
    expected_snapshot: RepositorySnapshot,
) -> Iterator[MaterializedExecutionSubject]:
    """Freeze the admissible pytest filesystem namespace into a bounded private tree.

    Tracked regular worktree files, non-ignored untracked regular files, and any
    physical path already covered by ``changed_files`` are copied through confined
    no-follow reads. Ordinary Git-ignored inputs and ``.git`` metadata are absent.
    Unchanged tracked bytes are checked against their index blob ids; changed bytes
    must reconstruct the exact repository fingerprint supplied by the caller.
    """

    _require_complete_git_snapshot(expected_snapshot)
    inspector = RepositoryInspector(workspace)
    observed_snapshot = inspector.snapshot()
    if not _same_snapshot(expected_snapshot, observed_snapshot):
        raise ExecutionSubjectError("repository subject changed before pytest materialization")

    object_format = inspector._git("rev-parse", "--show-object-format")
    if object_format not in {"sha1", "sha256"}:
        raise ExecutionSubjectError("repository object format is unavailable for materialization")
    raw_index_entries = inspector._git_bytes(
        "ls-files",
        "--stage",
        "-z",
        "--",
        max_stdout_bytes=_MAX_GIT_EXACT_STDOUT_BYTES,
    )
    if raw_index_entries is None:
        raise ExecutionSubjectError("repository index entries are unavailable for materialization")
    index_entries, unmerged = inspector._parse_index_entries(raw_index_entries)
    if unmerged:
        raise ExecutionSubjectError("unmerged index entries cannot enter pytest execution")
    if any(mode not in {"100644", "100755"} for mode, _oid in index_entries.values()):
        raise ExecutionSubjectError("non-regular tracked entries cannot enter pytest execution")

    untracked = inspector._git_path_list(
        "ls-files", "--others", "--exclude-standard", "-z", "--"
    )
    changed_set = set(expected_snapshot.changed_files)
    unexpected_untracked = sorted(path for path in untracked if path not in changed_set)
    if unexpected_untracked:
        raise ExecutionSubjectError("repository untracked namespace changed after subject snapshot")

    candidates = set(index_entries)
    candidates.update(untracked)
    candidates.update(expected_snapshot.changed_files)
    if len(candidates) > _MAX_GIT_PATHS:
        raise ExecutionSubjectError("pytest execution subject exceeds its bounded path budget")
    if any(path == ".git" or path.startswith(".git/") for path in candidates):
        raise ExecutionSubjectError("Git metadata cannot enter the pytest execution namespace")

    index_digest = hashlib.sha256(inspector._read_index_bytes()).hexdigest()
    copied_changed: dict[str, tuple[int, str]] = {}
    manifest_rows: list[dict[str, object]] = []
    total_bytes = 0

    with tempfile.TemporaryDirectory(prefix="aiqa-pytest-subject-") as temp_root_text:
        temp_root = Path(temp_root_text).absolute()
        temp_root_identity = pin_directory_identity(
            temp_root,
            label="pytest materialized execution subject",
        )

        for relative in sorted(candidates):
            try:
                entry = inspector._stat_confined_entry_adapter(
                    inspector.workspace,
                    relative,
                    label=f"pytest execution subject {relative}",
                    expected_root_identity=inspector.workspace_root_identity,
                )
            except FileNotFoundError:
                if relative in untracked or relative not in changed_set:
                    raise ExecutionSubjectError(
                        f"pytest execution subject disappeared during materialization: {relative}"
                    ) from None
                continue
            except (OSError, ValueError) as exc:
                raise ExecutionSubjectError(
                    f"pytest execution subject could not be observed safely: {relative}"
                ) from exc

            if not stat.S_ISREG(entry.st_mode):
                raise ExecutionSubjectError(
                    f"non-regular path cannot enter pytest execution: {relative}"
                )
            if entry.st_size > _MAX_FINGERPRINT_FILE_BYTES:
                raise ExecutionSubjectError(
                    f"pytest execution file exceeds bounded byte budget: {relative}"
                )
            if total_bytes + entry.st_size > _MAX_EXECUTION_SUBJECT_TOTAL_BYTES:
                raise ExecutionSubjectError("pytest execution subject exceeds total byte budget")

            try:
                data = inspector._read_bytes_confined_adapter(
                    inspector.workspace,
                    relative,
                    max_bytes=max(1, entry.st_size),
                    label=f"pytest execution subject {relative}",
                    expected_root_identity=inspector.workspace_root_identity,
                )
            except (OSError, ValueError) as exc:
                raise ExecutionSubjectError(
                    f"pytest execution subject bytes could not be frozen safely: {relative}"
                ) from exc
            if len(data) != entry.st_size:
                raise ExecutionSubjectError(
                    f"pytest execution subject changed size during materialization: {relative}"
                )

            index_entry = index_entries.get(relative)
            executable = bool(entry.st_mode & 0o111)
            if index_entry is not None and relative not in changed_set:
                mode, oid = index_entry
                if inspector._raw_blob_oid(data, object_format) != oid:
                    raise ExecutionSubjectError(
                        f"unchanged tracked bytes diverged from Git index during materialization: {relative}"
                    )
                if executable != (mode == "100755"):
                    raise ExecutionSubjectError(
                        f"unchanged tracked mode diverged from Git index during materialization: {relative}"
                    )

            digest = hashlib.sha256(data).hexdigest()
            atomic_write_bytes_confined(
                temp_root,
                relative,
                data,
                create_parents=True,
                create_only=True,
                label=f"pytest materialized execution subject {relative}",
                expected_root_identity=temp_root_identity,
            )
            target = temp_root / relative
            os.chmod(target, 0o755 if executable else 0o644, follow_symlinks=False)
            total_bytes += len(data)
            manifest_rows.append(
                {
                    "path": relative,
                    "mode": "100755" if executable else "100644",
                    "size": len(data),
                    "sha256": digest,
                }
            )
            if relative in changed_set:
                copied_changed[relative] = (len(data), digest)

        materialized_fingerprint = _fingerprint_from_materialized_changed_files(
            expected_snapshot,
            index_digest=index_digest,
            copied=copied_changed,
        )
        if materialized_fingerprint != expected_snapshot.fingerprint:
            raise ExecutionSubjectError(
                "materialized changed bytes do not match the authorized repository fingerprint"
            )

        final_snapshot = RepositoryInspector(workspace).snapshot()
        if not _same_snapshot(expected_snapshot, final_snapshot):
            raise ExecutionSubjectError("repository subject changed during pytest materialization")

        payload = {
            "schema_version": 1,
            "git_sha": expected_snapshot.git_sha,
            "source_fingerprint": expected_snapshot.fingerprint,
            "files": manifest_rows,
            "ignored_inputs_excluded": True,
            "git_metadata_excluded": True,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
        final_root_identity = pin_directory_identity(
            temp_root,
            label="pytest materialized execution subject",
        )
        if final_root_identity != temp_root_identity:
            raise ExecutionSubjectError("materialized pytest execution root changed identity")

        yield MaterializedExecutionSubject(
            root=temp_root,
            root_identity=final_root_identity,
            git_sha=expected_snapshot.git_sha,
            source_fingerprint=expected_snapshot.fingerprint,
            digest=digest,
            file_count=len(manifest_rows),
            total_bytes=total_bytes,
        )
