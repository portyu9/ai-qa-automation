from __future__ import annotations

import hashlib
import json
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..fs_authority import atomic_write_bytes_confined, pin_directory_identity
from ._repository_common import (
    _MAX_FINGERPRINT_CHANGED_FILES,
    _MAX_FINGERPRINT_FILE_BYTES,
    _MAX_FINGERPRINT_TOTAL_BYTES,
    _MAX_GIT_PATHS,
    _git_index_oid_bytes,
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


def _require_complete_git_snapshot(snapshot: RepositorySnapshot) -> str:
    if snapshot.git_sha is None:
        raise ExecutionSubjectError("pytest execution requires a Git-backed target workspace")
    if not snapshot.fingerprint_complete:
        reasons = ",".join(snapshot.fingerprint_incomplete_reasons)
        suffix = f" ({reasons})" if reasons else ""
        raise ExecutionSubjectError(f"workspace fingerprint is incomplete{suffix}")
    if len(snapshot.changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
        raise ExecutionSubjectError(
            "workspace changed-file subject exceeds its bounded file budget"
        )
    return snapshot.git_sha


def _decode_index_v4_strip_count(raw: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset >= limit:
        raise ExecutionSubjectError("Git index v4 entry is truncated")
    value = raw[offset] & 0x7F
    byte = raw[offset]
    offset += 1
    consumed = 1
    while byte & 0x80:
        if offset >= limit or consumed >= 10:
            raise ExecutionSubjectError("Git index v4 path compression is malformed")
        byte = raw[offset]
        offset += 1
        consumed += 1
        value = ((value + 1) << 7) + (byte & 0x7F)
    return value, offset


def _validate_index_path(raw_path: bytes) -> str:
    try:
        path = raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ExecutionSubjectError("Git index contains a non-UTF-8 path") from exc
    candidate = PurePosixPath(path)
    normalized = candidate.as_posix()
    if (
        not path
        or "\0" in path
        or candidate.is_absolute()
        or normalized != path
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ExecutionSubjectError("Git index contains an unsafe repository path")
    return normalized


def _parse_bound_index_entries(raw: bytes) -> tuple[dict[str, tuple[str, str]], str]:
    """Parse stage-zero entries from the exact raw index bytes bound by the fingerprint."""

    if len(raw) < 32 or raw[:4] != b"DIRC":
        raise ExecutionSubjectError("Git index header is malformed")
    version = int.from_bytes(raw[4:8], "big")
    entry_count = int.from_bytes(raw[8:12], "big")
    if version not in {2, 3, 4}:
        raise ExecutionSubjectError("Git index version is unsupported")
    if entry_count > _MAX_GIT_PATHS:
        raise ExecutionSubjectError("Git index entry count exceeds the bounded path budget")

    try:
        oid_bytes = _git_index_oid_bytes(raw)
    except RuntimeError as exc:
        raise ExecutionSubjectError("Git index checksum is invalid or ambiguous") from exc
    object_format = "sha1" if oid_bytes == 20 else "sha256"
    content_end = len(raw) - oid_bytes
    offset = 12
    previous_path = b""
    entries: dict[str, tuple[str, str]] = {}
    seen_records: set[tuple[str, int]] = set()
    unmerged = False

    for _ in range(entry_count):
        entry_start = offset
        fixed_bytes = 40 + oid_bytes + 2
        if offset + fixed_bytes > content_end:
            raise ExecutionSubjectError("Git index entry is truncated")
        mode_value = int.from_bytes(raw[offset + 24 : offset + 28], "big")
        oid = raw[offset + 40 : offset + 40 + oid_bytes].hex()
        flags_offset = offset + 40 + oid_bytes
        flags = int.from_bytes(raw[flags_offset : flags_offset + 2], "big")
        stage = (flags >> 12) & 0x3
        offset += fixed_bytes

        if flags & 0x4000:
            if version < 3 or offset + 2 > content_end:
                raise ExecutionSubjectError("Git index extended flags are malformed")
            offset += 2

        if version in {2, 3}:
            nul = raw.find(b"\0", offset, content_end)
            if nul < 0:
                raise ExecutionSubjectError("Git index pathname is not NUL terminated")
            raw_path = raw[offset:nul]
            stored_length = flags & 0x0FFF
            if stored_length < 0x0FFF and stored_length != len(raw_path):
                raise ExecutionSubjectError("Git index pathname length is inconsistent")
            if stored_length == 0x0FFF and len(raw_path) < 0x0FFF:
                raise ExecutionSubjectError("Git index long-path marker is inconsistent")
            consumed = nul + 1 - entry_start
            next_offset = entry_start + ((consumed + 7) // 8) * 8
            if next_offset > content_end or any(raw[nul + 1 : next_offset]):
                raise ExecutionSubjectError("Git index entry padding is malformed")
            offset = next_offset
            previous_path = raw_path
        else:
            strip_count, offset = _decode_index_v4_strip_count(raw, offset, content_end)
            if strip_count > len(previous_path):
                raise ExecutionSubjectError(
                    "Git index v4 path compression exceeds the previous path"
                )
            nul = raw.find(b"\0", offset, content_end)
            if nul < 0:
                raise ExecutionSubjectError("Git index v4 pathname is not NUL terminated")
            raw_path = previous_path[: len(previous_path) - strip_count] + raw[offset:nul]
            stored_length = flags & 0x0FFF
            if stored_length < 0x0FFF and stored_length != len(raw_path):
                raise ExecutionSubjectError("Git index v4 pathname length is inconsistent")
            if stored_length == 0x0FFF and len(raw_path) < 0x0FFF:
                raise ExecutionSubjectError("Git index v4 long-path marker is inconsistent")
            previous_path = raw_path
            offset = nul + 1

        path = _validate_index_path(raw_path)
        record_key = (path, stage)
        if record_key in seen_records:
            raise ExecutionSubjectError("Git index contains duplicate path/stage entries")
        seen_records.add(record_key)
        if stage != 0:
            unmerged = True
            continue
        if path in entries:
            raise ExecutionSubjectError("Git index contains duplicate stage-zero entries")
        mode = f"{mode_value:o}"
        entries[path] = (mode, oid)

    while offset < content_end:
        if offset + 8 > content_end:
            raise ExecutionSubjectError("Git index extension header is truncated")
        signature = raw[offset : offset + 4]
        size = int.from_bytes(raw[offset + 4 : offset + 8], "big")
        next_offset = offset + 8 + size
        if next_offset > content_end:
            raise ExecutionSubjectError("Git index extension exceeds the bounded index bytes")
        if signature == b"link":
            raise ExecutionSubjectError("split Git indexes cannot enter pytest execution")
        if b"a" <= signature[:1] <= b"z":
            raise ExecutionSubjectError("unsupported mandatory Git index extension")
        offset = next_offset
    if offset != content_end:
        raise ExecutionSubjectError("Git index extension framing is malformed")
    if unmerged:
        raise ExecutionSubjectError("unmerged index entries cannot enter pytest execution")
    return entries, object_format


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
    scratch_root: Path,
    expected_scratch_root_identity: tuple[int, int],
) -> Iterator[MaterializedExecutionSubject]:
    """Freeze the admissible pytest filesystem namespace into a bounded private tree.

    Tracked regular worktree files, non-ignored untracked regular files, and any
    physical path already covered by ``changed_files`` are copied through confined
    no-follow reads. Ordinary Git-ignored inputs and ``.git`` metadata are absent.
    Unchanged tracked bytes are checked against OIDs parsed from the same raw Git
    index bytes whose digest is already bound by the repository fingerprint.
    Executable authority is admitted only when the stage-zero index binds that mode;
    executable untracked or unstaged-mode-divergent paths fail closed. Changed bytes
    must reconstruct the exact authorized repository fingerprint.
    """

    expected_git_sha = _require_complete_git_snapshot(expected_snapshot)
    inspector = RepositoryInspector(workspace)
    trusted_scratch_root = scratch_root.expanduser().absolute()
    if (
        trusted_scratch_root == inspector.workspace
        or trusted_scratch_root in inspector.workspace.parents
        or inspector.workspace in trusted_scratch_root.parents
    ):
        raise ExecutionSubjectError("pytest scratch root overlaps the target workspace")
    try:
        scratch_identity = pin_directory_identity(
            trusted_scratch_root,
            label="pytest scratch root",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        raise ExecutionSubjectError("pytest scratch-root authority is unavailable") from exc
    if scratch_identity != expected_scratch_root_identity:
        raise ExecutionSubjectError("pytest scratch root changed identity since authorization")
    observed_snapshot = inspector.snapshot()
    if not _same_snapshot(expected_snapshot, observed_snapshot):
        raise ExecutionSubjectError("repository subject changed before pytest materialization")

    raw_index = inspector._read_index_bytes()
    index_digest = hashlib.sha256(raw_index).hexdigest()
    index_entries, object_format = _parse_bound_index_entries(raw_index)
    if any(mode not in {"100644", "100755"} for mode, _oid in index_entries.values()):
        raise ExecutionSubjectError("non-regular tracked entries cannot enter pytest execution")

    untracked = inspector._git_path_list("ls-files", "--others", "--exclude-standard", "-z", "--")
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

    copied_changed: dict[str, tuple[int, str]] = {}
    manifest_rows: list[dict[str, object]] = []
    total_bytes = 0

    with tempfile.TemporaryDirectory(
        prefix="aiqa-pytest-subject-",
        dir=trusted_scratch_root,
    ) as temp_root_text:
        try:
            current_scratch_identity = pin_directory_identity(
                trusted_scratch_root,
                label="pytest scratch root",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise ExecutionSubjectError("pytest scratch-root authority became unavailable") from exc
        if current_scratch_identity != expected_scratch_root_identity:
            raise ExecutionSubjectError("pytest scratch root changed during subject creation")
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
            observed_executable = bool(entry.st_mode & 0o111)
            if index_entry is None:
                if observed_executable:
                    raise ExecutionSubjectError(
                        f"executable path lacks Git-index mode authority: {relative}"
                    )
                executable = False
                materialized_mode = "100644"
            else:
                index_mode, oid = index_entry
                executable = index_mode == "100755"
                if observed_executable != executable:
                    raise ExecutionSubjectError(
                        f"worktree executable mode diverges from Git index: {relative}"
                    )
                materialized_mode = index_mode
                if (
                    relative not in changed_set
                    and inspector._raw_blob_oid(data, object_format) != oid
                ):
                    raise ExecutionSubjectError(
                        "unchanged tracked bytes diverged from Git index during "
                        f"materialization: {relative}"
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
            target.chmod(0o755 if executable else 0o644)
            total_bytes += len(data)
            manifest_rows.append(
                {
                    "path": relative,
                    "mode": materialized_mode,
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
            "index_sha256": index_digest,
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
        try:
            final_scratch_identity = pin_directory_identity(
                trusted_scratch_root,
                label="pytest scratch root",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise ExecutionSubjectError("pytest scratch-root authority became unavailable") from exc
        if final_scratch_identity != expected_scratch_root_identity:
            raise ExecutionSubjectError("pytest scratch root changed during materialization")

        yield MaterializedExecutionSubject(
            root=temp_root,
            root_identity=final_root_identity,
            git_sha=expected_git_sha,
            source_fingerprint=expected_snapshot.fingerprint,
            digest=digest,
            file_count=len(manifest_rows),
            total_bytes=total_bytes,
        )
