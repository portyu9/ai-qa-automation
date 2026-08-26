from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
)
from ..fs_observation import scan_regular_files_confined
from ..io_safety import open_regular_binary
from .execution_env import (
    restricted_subprocess_env,
    run_bounded_binary_subprocess,
    run_bounded_subprocess,
)
from .subprocess_subject import active_workspace_authority, descriptor_bound_cwd

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_GIT_MODE = re.compile(r"^[0-7]{6}$")
_GIT_GRAFT_WARNING = "info/grafts"
_DESCRIPTOR_PATH_ROOTS = (Path("/proc/self/fd"), Path("/dev/fd"))
_MAX_FINGERPRINT_CHANGED_FILES = 1000
_MAX_FINGERPRINT_FILE_BYTES = 16_000_000
_MAX_FINGERPRINT_TOTAL_BYTES = 128_000_000
_MAX_UNTRACKED_PATHS = 20_000
_MAX_GIT_METADATA_SCAN_ENTRIES = 100_000
_MAX_STATUS_BYTES = 8_000_000
_MAX_GIT_TEXT_OUTPUT_BYTES = 8_000_000
_MAX_GIT_EXACT_STDOUT_BYTES = 16_000_000
_MAX_GIT_EXACT_STDERR_BYTES = 256_000
_MAX_GIT_INDEX_BYTES = 16_000_000
_REGULAR_GIT_MODES = {"100644", "100755"}


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stable_file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _descriptor_path(directory_fd: int, *, label: str) -> Path:
    opened = os.fstat(directory_fd)
    expected = _identity(opened)
    if not stat.S_ISDIR(opened.st_mode):
        raise ValueError(f"{label} descriptor does not reference a directory")
    for root in _DESCRIPTOR_PATH_ROOTS:
        candidate = root / str(directory_fd)
        try:
            observed = candidate.stat()
        except OSError:
            continue
        if stat.S_ISDIR(observed.st_mode) and _identity(observed) == expected:
            return candidate
    raise RuntimeError(f"{label} requires a descriptor-backed directory path")


def _raise_if_git_grafts_reported(stderr: str) -> None:
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


@dataclass(frozen=True)
class _GitEntry:
    mode: str
    object_id: str


@dataclass(frozen=True)
class _WorktreeState:
    status: str
    changed_files: tuple[str, ...]
    incomplete_reasons: tuple[str, ...]
    index_sha256: str


class RepositoryInspector:
    """Read-only Git inspection with subject-bound raw worktree observation.

    Git is restricted to metadata/object plumbing. Worktree content is read through
    no-follow descriptor confinement, so target-configured clean/textconv/external-diff
    programs cannot execute as a side effect of repository inspection.
    """

    def __init__(
        self,
        workspace: Path,
        timeout_seconds: int = 20,
        *,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 1
        ):
            raise ValueError("repository inspection timeout_seconds must be a positive integer")
        if expected_root_identity is not None and (
            not isinstance(expected_root_identity, tuple)
            or len(expected_root_identity) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in expected_root_identity
            )
        ):
            raise ValueError("expected_root_identity must be a pair of non-negative integers")

        self.workspace = workspace.expanduser().absolute()
        self.timeout_seconds = timeout_seconds
        active_identity = active_workspace_authority(self.workspace)
        if (
            expected_root_identity is not None
            and active_identity is not None
            and expected_root_identity != active_identity
        ):
            raise RepositorySubjectError(
                "explicit repository authority conflicts with the active workspace lease"
            )
        authorized_identity = expected_root_identity or active_identity
        self.workspace_root_identity: tuple[int, int] | None = None
        self.git_dir_identity: tuple[int, int] | None = None
        self.git_objects_identity: tuple[int, int] | None = None
        self.git_refs_identity: tuple[int, int] | None = None

        if descriptor_relative_authority_supported():
            try:
                current_identity = pin_directory_identity(
                    self.workspace, label="repository inspection workspace"
                )
            except (OSError, RuntimeError, ValueError) as exc:
                raise RepositorySubjectError(
                    "repository workspace identity could not be pinned"
                ) from exc
            if authorized_identity is not None and current_identity != authorized_identity:
                raise RepositorySubjectError(
                    "repository workspace changed identity since authorization"
                )
            self.workspace_root_identity = current_identity
            try:
                self.git_dir_identity = self._pin_direct_directory(
                    self.workspace,
                    ".git",
                    expected_root_identity=current_identity,
                    label="repository Git metadata directory",
                )
                if self.git_dir_identity is not None:
                    self.git_objects_identity = self._pin_direct_directory(
                        self.workspace / ".git",
                        "objects",
                        expected_root_identity=self.git_dir_identity,
                        label="repository Git object directory",
                    )
                    self.git_refs_identity = self._pin_direct_directory(
                        self.workspace / ".git",
                        "refs",
                        expected_root_identity=self.git_dir_identity,
                        label="repository Git refs directory",
                    )
                    if self.git_objects_identity is None or self.git_refs_identity is None:
                        raise ValueError("Git objects/refs directories are required")
                    self._assert_git_metadata_tree_safe()
                    self._reject_external_git_metadata_indirection()
            except RepositorySubjectError:
                raise
            except (OSError, RuntimeError, ValueError) as exc:
                raise RepositorySubjectError(
                    "repository Git metadata must be direct, no-follow, and self-contained"
                ) from exc
        elif authorized_identity is not None:
            raise RepositorySubjectError(
                "authorized repository inspection requires descriptor-bound filesystem authority"
            )

    @staticmethod
    def _pin_direct_directory(
        root: Path,
        name: str,
        *,
        expected_root_identity: tuple[int, int],
        label: str,
    ) -> tuple[int, int] | None:
        if not descriptor_relative_authority_supported():
            raise RuntimeError(f"{label} requires descriptor-relative filesystem authority")
        if not name or name in {".", ".."} or Path(name).name != name:
            raise ValueError(f"{label} must name one direct child directory")
        root = root.expanduser().absolute()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            root_fd = os.open(root, flags)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError(f"{label} root became a symlink or non-directory") from exc
            raise
        try:
            opened_root = os.fstat(root_fd)
            current_root = root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or not stat.S_ISDIR(current_root.st_mode)
                or _identity(opened_root) != expected_root_identity
                or _identity(current_root) != expected_root_identity
            ):
                raise ValueError(f"{label} root changed identity since authorization")
            try:
                child_fd = os.open(name, flags, dir_fd=root_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise ValueError(f"{label} must be a direct no-follow directory") from exc
                raise
            try:
                opened_child = os.fstat(child_fd)
                current_child = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_child.st_mode)
                    or not stat.S_ISDIR(current_child.st_mode)
                    or _identity(opened_child) != _identity(current_child)
                ):
                    raise ValueError(f"{label} changed identity during authority pinning")
                return _identity(opened_child)
            finally:
                os.close(child_fd)
        finally:
            os.close(root_fd)

    def _assert_workspace_subject_current(self) -> None:
        if self.workspace_root_identity is None:
            return
        try:
            current_identity = pin_directory_identity(
                self.workspace, label="repository inspection workspace"
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository workspace subject could not be revalidated"
            ) from exc
        if current_identity != self.workspace_root_identity:
            raise RepositorySubjectError("repository workspace changed identity during inspection")

    def _assert_git_metadata_tree_safe(self) -> None:
        if self.git_dir_identity is None:
            return
        try:
            scan = scan_regular_files_confined(
                self.workspace / ".git",
                max_entries=_MAX_GIT_METADATA_SCAN_ENTRIES,
                label="repository Git metadata observation",
                expected_root_identity=self.git_dir_identity,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository Git metadata tree could not be inspected safely"
            ) from exc
        if scan.unsafe_paths or scan.unreadable_paths:
            raise RepositorySubjectError(
                "repository Git metadata tree contains unsafe or unreadable entries"
            )
        if scan.truncated:
            raise RuntimeError("repository Git metadata scan exceeded its bounded entry budget")

    def _reject_external_git_metadata_indirection(self) -> None:
        if self.git_dir_identity is None:
            return
        checks = (
            ("commondir", "Git common-directory indirection"),
            ("objects/info/alternates", "Git alternate-object indirection"),
            ("objects/info/http-alternates", "Git HTTP alternate-object indirection"),
        )
        for relative, label in checks:
            try:
                data = read_bytes_confined(
                    self.workspace / ".git",
                    relative,
                    max_bytes=256_000,
                    label=label,
                    expected_root_identity=self.git_dir_identity,
                )
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                raise RepositorySubjectError(
                    "repository Git metadata indirection could not be inspected safely"
                ) from exc
            if relative == "commondir" or data.strip():
                raise RepositorySubjectError(
                    "repository Git metadata must not redirect to external common/object storage"
                )

    def _assert_git_subject_current(self) -> None:
        self._assert_workspace_subject_current()
        if self.workspace_root_identity is None or self.git_dir_identity is None:
            return
        try:
            current = self._pin_direct_directory(
                self.workspace,
                ".git",
                expected_root_identity=self.workspace_root_identity,
                label="repository Git metadata directory",
            )
            objects = self._pin_direct_directory(
                self.workspace / ".git",
                "objects",
                expected_root_identity=self.git_dir_identity,
                label="repository Git object directory",
            )
            refs = self._pin_direct_directory(
                self.workspace / ".git",
                "refs",
                expected_root_identity=self.git_dir_identity,
                label="repository Git refs directory",
            )
            self._assert_git_metadata_tree_safe()
            self._reject_external_git_metadata_indirection()
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository Git metadata subject could not be revalidated"
            ) from exc
        if (
            current != self.git_dir_identity
            or objects != self.git_objects_identity
            or refs != self.git_refs_identity
        ):
            raise RepositorySubjectError(
                "repository Git metadata changed identity during inspection"
            )

    def snapshot(self) -> RepositorySnapshot:
        try:
            sha = self._git("rev-parse", "HEAD", allow_failure=True)
            branch = self._git(
                "symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True
            )
            if self.git_dir_identity is None:
                fingerprint, complete, reasons = self._fingerprint(None, "", ())
                return RepositorySnapshot(
                    workspace=str(self.workspace),
                    git_sha=None,
                    branch=None,
                    status="",
                    changed_files=(),
                    fingerprint=fingerprint,
                    fingerprint_complete=complete,
                    fingerprint_incomplete_reasons=reasons,
                )
            object_format = self._git("rev-parse", "--show-object-format")
            if object_format not in {"sha1", "sha256"}:
                raise RuntimeError("Git returned an unsupported object format")
            state = self._observe_worktree(sha, object_format)
            final_sha = self._git("rev-parse", "HEAD", allow_failure=True)
            if final_sha != sha:
                raise RuntimeError("Git HEAD changed during repository inspection")
            final_index = self._read_index_bytes()
            if hashlib.sha256(final_index).hexdigest() != state.index_sha256:
                raise RuntimeError("Git index changed during repository inspection")
            self._assert_git_subject_current()
        except RepositorySubjectError:
            raise
        except RuntimeError as exc:
            message = str(exc).casefold()
            reason = (
                "git-inspection-timeout"
                if "exceeded" in message and "budget" in message
                else "git-inspection-incomplete"
            )
            return self._incomplete_snapshot(reason)

        fingerprint, complete, reasons = self._fingerprint(
            sha,
            state.status,
            state.changed_files,
            index_sha256=state.index_sha256,
            initial_incomplete_reasons=state.incomplete_reasons,
        )
        self._assert_git_subject_current()
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=sha or None,
            branch=branch or None,
            status=state.status,
            changed_files=state.changed_files,
            fingerprint=fingerprint,
            fingerprint_complete=complete,
            fingerprint_incomplete_reasons=reasons,
        )

    def _incomplete_snapshot(self, reason: str) -> RepositorySnapshot:
        payload = {
            "workspace": str(self.workspace),
            "fingerprint_complete": False,
            "fingerprint_incomplete_reasons": [reason],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=None,
            branch=None,
            status="!! GIT_INSPECTION_INCOMPLETE",
            changed_files=(),
            fingerprint=f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
            fingerprint_complete=False,
            fingerprint_incomplete_reasons=(reason,),
        )

    def change_set(self, base_ref: str) -> RepositoryChangeSet:
        safe_ref = self._validate_ref(base_ref)
        head = self._git("rev-parse", "HEAD")
        if head is None:
            raise RuntimeError("target workspace is not a Git repository")
        baseline = self._git("rev-parse", "--verify", f"{safe_ref}^{{commit}}")
        if baseline is None:
            raise RuntimeError(f"baseline ref could not be resolved: {safe_ref}")
        merge_base = self._git("merge-base", baseline, head)
        if merge_base is None:
            raise RuntimeError(f"baseline ref has no merge base with HEAD: {safe_ref}")
        committed = self._changed_paths_between_trees(merge_base, head)
        worktree_snapshot = self.snapshot()
        if not worktree_snapshot.fingerprint_complete:
            raise RuntimeError("worktree status inspection is incomplete")
        if worktree_snapshot.git_sha != head:
            raise RuntimeError("Git HEAD changed during change-set inspection")
        worktree = worktree_snapshot.changed_files
        return RepositoryChangeSet(
            requested_base_ref=safe_ref,
            baseline_sha=baseline,
            merge_base_sha=merge_base,
            head_sha=head,
            committed_files=committed,
            worktree_files=worktree,
            changed_files=tuple(sorted(set(committed) | set(worktree))),
        )

    def _changed_paths_between_trees(self, left: str, right: str) -> tuple[str, ...]:
        left_entries = self._tree_entries_at(left)
        right_entries = self._tree_entries_at(right)
        return tuple(
            sorted(
                path
                for path in set(left_entries) | set(right_entries)
                if left_entries.get(path) != right_entries.get(path)
            )
        )

    def _tree_entries_at(self, commit_sha: str) -> dict[str, _GitEntry]:
        raw = self._git_bytes(
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit_sha,
            max_stdout_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES,
        )
        if raw is None:
            raise RuntimeError("Git tree enumeration returned no result")
        entries: dict[str, _GitEntry] = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise RuntimeError("Git returned a malformed tree entry")
            try:
                fields = metadata.decode("ascii").split()
                path = self._validate_relative_path(raw_path.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned invalid tree metadata/path") from exc
            if len(fields) != 3:
                raise RuntimeError("Git returned a malformed tree entry")
            mode, object_type, object_id = fields
            if (
                not _GIT_MODE.fullmatch(mode)
                or object_type not in {"blob", "commit"}
                or not _HEX_SHA.fullmatch(object_id)
                or path in entries
            ):
                raise RuntimeError("Git returned a malformed or ambiguous tree entry")
            entries[path] = _GitEntry(mode=mode, object_id=object_id.lower())
        return entries

    def _index_entries(self) -> tuple[dict[str, _GitEntry], set[str], tuple[str, ...], str]:
        before = self._read_index_bytes()
        raw = self._git_bytes(
            "ls-files", "--stage", "-z", max_stdout_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES
        )
        if raw is None:
            raise RuntimeError("Git index enumeration returned no result")
        after = self._read_index_bytes()
        if before != after:
            raise RuntimeError("Git index changed during index enumeration")
        entries: dict[str, _GitEntry] = {}
        unmerged: set[str] = set()
        reasons: set[str] = set()
        seen_records: set[tuple[str, int]] = set()
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise RuntimeError("Git returned a malformed index entry")
            try:
                fields = metadata.decode("ascii").split()
                path = self._validate_relative_path(raw_path.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned invalid index metadata/path") from exc
            if len(fields) != 3:
                raise RuntimeError("Git returned a malformed index entry")
            mode, object_id, raw_stage = fields
            try:
                stage = int(raw_stage)
            except ValueError as exc:
                raise RuntimeError("Git returned a malformed index stage") from exc
            key = (path, stage)
            if (
                not _GIT_MODE.fullmatch(mode)
                or not _HEX_SHA.fullmatch(object_id)
                or stage not in {0, 1, 2, 3}
                or key in seen_records
            ):
                raise RuntimeError("Git returned a malformed or ambiguous index entry")
            seen_records.add(key)
            if stage != 0:
                unmerged.add(path)
                reasons.add("index-unmerged-entry")
                continue
            if path in entries:
                raise RuntimeError("Git returned duplicate stage-zero index entries")
            entries[path] = _GitEntry(mode=mode, object_id=object_id.lower())
        return entries, unmerged, tuple(sorted(reasons)), hashlib.sha256(before).hexdigest()

    def _read_index_bytes(self) -> bytes:
        if self.git_dir_identity is None:
            return b""
        self._assert_git_subject_current()
        try:
            data = read_bytes_confined(
                self.workspace / ".git",
                "index",
                max_bytes=_MAX_GIT_INDEX_BYTES,
                label="Git index",
                expected_root_identity=self.git_dir_identity,
            )
        except FileNotFoundError:
            data = b""
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "Git index could not be read through confined metadata authority"
            ) from exc
        self._assert_git_subject_current()
        return data

    def _untracked_paths(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        raw = self._git_worktree_bytes(
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            max_stdout_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES,
        )
        paths: list[str] = []
        reasons: set[str] = set()
        seen: set[str] = set()
        for raw_path in raw.split(b"\0"):
            if not raw_path:
                continue
            try:
                path = self._validate_relative_path(raw_path.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise RuntimeError("Git returned an invalid untracked worktree path") from exc
            if path in seen:
                raise RuntimeError("Git returned duplicate untracked worktree paths")
            seen.add(path)
            if len(paths) < _MAX_UNTRACKED_PATHS:
                paths.append(path)
            else:
                reasons.add("worktree-untracked-path-limit-exceeded")
        return tuple(sorted(paths)), tuple(sorted(reasons))

    def _observe_worktree(self, head_sha: str | None, object_format: str) -> _WorktreeState:
        if self.workspace_root_identity is None:
            raise RuntimeError(
                "worktree observation requires descriptor-relative filesystem authority"
            )
        index, unmerged, index_reasons, index_sha256 = self._index_entries()
        head = self._tree_entries_at(head_sha) if head_sha is not None else {}
        untracked, untracked_reasons = self._untracked_paths()
        reasons = set(index_reasons) | set(untracked_reasons)
        status_codes: dict[str, list[str]] = {}

        for path in sorted(set(head) | set(index) | unmerged):
            if path in unmerged:
                status_codes[path] = ["U", "U"]
                continue
            head_entry = head.get(path)
            index_entry = index.get(path)
            if head_entry == index_entry:
                continue
            if head_entry is None:
                code = "A"
            elif index_entry is None:
                code = "D"
            else:
                code = "M"
            status_codes.setdefault(path, [" ", " "])[0] = code

        compared_bytes = 0
        for path, entry in sorted(index.items()):
            codes = status_codes.setdefault(path, [" ", " "])
            if entry.mode not in _REGULAR_GIT_MODES:
                codes[1] = "M"
                reasons.add("tracked-nonregular-worktree-unverified")
                continue
            remaining = _MAX_FINGERPRINT_TOTAL_BYTES - compared_bytes
            if remaining <= 0:
                codes[1] = "M"
                reasons.add("worktree-total-byte-limit-exceeded")
                continue
            try:
                data, mode = self._read_bytes_and_mode_confined(
                    path,
                    max_bytes=min(_MAX_FINGERPRINT_FILE_BYTES, remaining),
                    label=f"tracked worktree subject {path}",
                )
            except FileNotFoundError:
                codes[1] = "D"
                continue
            except OSError:
                codes[1] = "M"
                reasons.add("tracked-path-unreadable")
                continue
            except ValueError as exc:
                codes[1] = "M"
                message = str(exc).casefold()
                if "exceeds" in message:
                    reasons.add(
                        "worktree-total-byte-limit-exceeded"
                        if remaining < _MAX_FINGERPRINT_FILE_BYTES
                        else "worktree-file-byte-limit-exceeded"
                    )
                elif "symlink" in message:
                    reasons.add("tracked-path-unsafe")
                else:
                    reasons.add("tracked-path-observation-failed")
                continue
            compared_bytes += len(data)
            expected_executable = entry.mode == "100755"
            actual_executable = bool(mode & 0o111)
            if (
                self._raw_blob_oid(data, object_format) != entry.object_id
                or actual_executable != expected_executable
            ):
                codes[1] = "M"

        for path in untracked:
            if path not in index:
                status_codes.setdefault(path, ["?", "?"])

        status_lines: list[str] = []
        status_bytes = 0
        changed: list[str] = []
        for path in sorted(status_codes):
            x, y = status_codes[path]
            if x == " " and y == " ":
                continue
            changed.append(path)
            line = f"{x}{y} {self._render_status_path(path)}"
            encoded_size = len(line.encode("utf-8")) + (1 if status_lines else 0)
            if status_bytes + encoded_size <= _MAX_STATUS_BYTES:
                status_lines.append(line)
                status_bytes += encoded_size
            else:
                reasons.add("worktree-status-byte-limit-exceeded")
        return _WorktreeState(
            status="\n".join(status_lines),
            changed_files=tuple(changed),
            incomplete_reasons=tuple(sorted(reasons)),
            index_sha256=index_sha256,
        )

    def _read_bytes_and_mode_confined(
        self, relative: str, *, max_bytes: int, label: str
    ) -> tuple[bytes, int]:
        if self.workspace_root_identity is None:
            raise RuntimeError("confined mode observation requires workspace authority")
        path = PurePosixPath(self._validate_relative_path(relative))
        root = self.workspace
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(root, flags)
        current_fd = root_fd
        try:
            opened_root = os.fstat(root_fd)
            current_root = root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened_root.st_mode)
                or not stat.S_ISDIR(current_root.st_mode)
                or _identity(opened_root) != self.workspace_root_identity
                or _identity(current_root) != self.workspace_root_identity
            ):
                raise ValueError(f"{label} trusted root changed identity")
            for part in path.parts[:-1]:
                child_fd = os.open(part, flags, dir_fd=current_fd)
                opened_child = os.fstat(child_fd)
                current_child = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_child.st_mode)
                    or not stat.S_ISDIR(current_child.st_mode)
                    or _identity(opened_child) != _identity(current_child)
                ):
                    os.close(child_fd)
                    raise ValueError(f"{label} parent changed identity")
                if current_fd != root_fd:
                    os.close(current_fd)
                current_fd = child_fd
            file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | os.O_NOFOLLOW
            try:
                file_fd = os.open(path.parts[-1], file_flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError(f"{label} is a symlink") from exc
                raise
            try:
                opened = os.fstat(file_fd)
                current = os.stat(path.parts[-1], dir_fd=current_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(current.st_mode)
                    or _identity(opened) != _identity(current)
                ):
                    raise ValueError(f"{label} must be a stable regular file")
                initial = _stable_file_signature(opened)
                chunks: list[bytes] = []
                total = 0
                while total <= max_bytes:
                    chunk = os.read(file_fd, min(1024 * 1024, max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"{label} exceeds {max_bytes} byte ingestion limit")
                final_opened = os.fstat(file_fd)
                final_current = os.stat(
                    path.parts[-1], dir_fd=current_fd, follow_symlinks=False
                )
                if (
                    _stable_file_signature(final_opened) != initial
                    or not stat.S_ISREG(final_current.st_mode)
                    or _identity(final_opened) != _identity(final_current)
                ):
                    raise ValueError(f"{label} changed during confined read")
                return b"".join(chunks), final_opened.st_mode
            finally:
                os.close(file_fd)
        finally:
            if current_fd != root_fd:
                os.close(current_fd)
            os.close(root_fd)

    @staticmethod
    def _raw_blob_oid(data: bytes, object_format: str) -> str:
        header = f"blob {len(data)}\0".encode("ascii")
        if object_format == "sha1":
            return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
        if object_format == "sha256":
            return hashlib.sha256(header + data).hexdigest()
        raise RuntimeError("unsupported Git object format")

    def _blob_oid_at(self, commit_sha: str, path: str) -> str | None:
        raw = self._git(
            "ls-tree", "-z", "--full-tree", commit_sha, "--", f":(literal){path}"
        )
        if raw is None:
            raise RuntimeError("Git tree lookup returned no result")
        if raw == "":
            return None
        records = [record for record in raw.split("\0") if record]
        if len(records) != 1:
            raise RuntimeError("Git returned an ambiguous tree entry")
        metadata, separator, returned_path = records[0].partition("\t")
        if not separator or returned_path != path:
            raise RuntimeError("Git returned a malformed tree entry")
        fields = metadata.split()
        if len(fields) != 3:
            raise RuntimeError("Git returned a malformed tree entry")
        mode, object_type, object_id = fields
        if (
            not _GIT_MODE.fullmatch(mode)
            or object_type not in {"blob", "tree", "commit"}
            or not _HEX_SHA.fullmatch(object_id)
        ):
            raise RuntimeError("Git returned a malformed tree entry")
        if object_type != "blob":
            raise RuntimeError(f"baseline path is not a Git blob: {path}")
        return object_id.lower()

    def read_file_at(
        self, commit_sha: str, relative_path: str, *, max_bytes: int = 2_000_000
    ) -> bytes:
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= _MAX_GIT_EXACT_STDOUT_BYTES
        ):
            raise ValueError(
                f"max_bytes must be an integer between 1 and {_MAX_GIT_EXACT_STDOUT_BYTES}"
            )
        if not _HEX_SHA.fullmatch(commit_sha):
            raise ValueError("commit_sha must be a full hexadecimal object id")
        path = self._validate_relative_path(relative_path)
        blob_oid = self._blob_oid_at(commit_sha, path)
        if blob_oid is None:
            raise FileNotFoundError(path)
        size_text = self._git("cat-file", "-s", blob_oid)
        if size_text is None:
            raise RuntimeError("Git blob size lookup returned no result")
        try:
            size = int(size_text)
        except ValueError as exc:
            raise RuntimeError("Git returned an invalid object size") from exc
        if size < 0:
            raise RuntimeError("Git returned an invalid object size")
        if size > max_bytes:
            raise ValueError(f"baseline file exceeds {max_bytes} byte limit: {path}")
        result = self._git_bytes(
            "cat-file", "blob", blob_oid, max_stdout_bytes=max(1, size)
        )
        if result is None:
            raise RuntimeError("Git blob read returned no result")
        if len(result) != size:
            raise RuntimeError(
                "Git returned baseline bytes inconsistent with preflight object size"
            )
        self._assert_git_subject_current()
        return result

    def diff(self, *paths: str) -> str:
        """Return a safe status-level change summary without content conversion."""
        selected = {self._validate_relative_path(path) for path in paths}
        snapshot = self.snapshot()
        if not selected:
            return snapshot.status
        matching: list[str] = []
        for line in snapshot.status.splitlines():
            if len(line) >= 4 and self._parse_status_path(line[3:]) in selected:
                matching.append(line)
        return "\n".join(matching)

    @staticmethod
    def _validate_ref(base_ref: str) -> str:
        value = base_ref.strip()
        if not _SAFE_REF.fullmatch(value) or value.startswith("-") or ".." in value:
            raise ValueError(
                "baseline ref contains unsupported characters or revision-range syntax"
            )
        return value

    @staticmethod
    def _validate_relative_path(relative_path: str) -> str:
        if not isinstance(relative_path, str) or not relative_path or "\0" in relative_path:
            raise ValueError("repository path must be a normalized relative path")
        path = PurePosixPath(relative_path)
        normalized = path.as_posix()
        if (
            path.is_absolute()
            or normalized != relative_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise ValueError("repository path must be a normalized relative path")
        return normalized

    @staticmethod
    def _render_status_path(path: str) -> str:
        if (
            path[:1].isspace()
            or path[-1:].isspace()
            or any(
                ord(char) < 0x20
                or 0xD800 <= ord(char) <= 0xDFFF
                or char in {'"', "\\"}
                for char in path
            )
        ):
            return json.dumps(path, ensure_ascii=True)
        return path

    @staticmethod
    def _parse_status_path(rendered: str) -> str:
        if not rendered.startswith('"'):
            return rendered
        try:
            parsed = json.loads(rendered)
        except json.JSONDecodeError as exc:
            raise RuntimeError("repository status contains a malformed quoted path") from exc
        if not isinstance(parsed, str):
            raise RuntimeError("repository status contains a malformed quoted path")
        return parsed

    def _read_fingerprint_bytes(
        self, relative: str, *, max_bytes: int
    ) -> tuple[bytes | None, str | None]:
        try:
            normalized = self._validate_relative_path(relative)
        except ValueError:
            return None, "changed-path-outside-workspace"
        if self.workspace_root_identity is not None:
            try:
                data = read_bytes_confined(
                    self.workspace,
                    normalized,
                    max_bytes=max_bytes,
                    label=f"workspace fingerprint subject {normalized}",
                    expected_root_identity=self.workspace_root_identity,
                )
            except FileNotFoundError:
                self._assert_workspace_subject_current()
                return None, "deleted"
            except OSError:
                self._assert_workspace_subject_current()
                return None, "changed-file-unreadable"
            except ValueError as exc:
                message = str(exc).casefold()
                if "trusted root" in message:
                    raise RepositorySubjectError(
                        "workspace fingerprint subject changed root identity during inspection"
                    ) from exc
                if "symlink" in message and "parent component" not in message:
                    return None, "changed-symlink-not-byte-bound"
                if "must be a regular file" in message:
                    return None, "changed-non-file-not-byte-bound"
                if "exceeds" in message and "ingestion limit" in message:
                    return None, "byte-limit-exceeded"
                return None, "changed-path-ownership-ambiguous"
            return data, None

        raw_candidate = self.workspace / normalized
        if raw_candidate.is_symlink():
            return None, "changed-symlink-not-byte-bound"
        candidate = raw_candidate.resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError:
            return None, "changed-path-outside-workspace"
        if not candidate.exists():
            return None, "deleted"
        if not candidate.is_file():
            return None, "changed-non-file-not-byte-bound"
        try:
            size_hint = candidate.stat().st_size
        except OSError:
            return None, "changed-file-unreadable"
        if size_hint > max_bytes:
            return None, "byte-limit-exceeded"
        chunks: list[bytes] = []
        size = 0
        try:
            with open_regular_binary(
                candidate, label=f"workspace fingerprint subject {normalized}"
            ) as stream:
                while size <= max_bytes:
                    chunk = stream.read(min(1024 * 1024, max_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
        except OSError:
            return None, "changed-file-unreadable"
        except ValueError:
            return None, "changed-path-ownership-ambiguous"
        if size > max_bytes:
            return None, "byte-limit-exceeded"
        return b"".join(chunks), None

    def _fingerprint(
        self,
        git_sha: str | None,
        status: str,
        changed_files: tuple[str, ...],
        *,
        index_sha256: str = "unavailable",
        initial_incomplete_reasons: tuple[str, ...] = (),
    ) -> tuple[str, bool, tuple[str, ...]]:
        file_rows: list[dict[str, object]] = []
        incomplete_reasons = set(initial_incomplete_reasons)
        total_hashed_bytes = 0
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            incomplete_reasons.add("changed-file-limit-exceeded")
        for relative in changed_files[:_MAX_FINGERPRINT_CHANGED_FILES]:
            remaining = _MAX_FINGERPRINT_TOTAL_BYTES - total_hashed_bytes
            if remaining <= 0:
                file_rows.append({"path": relative, "state": "total-byte-limit-exceeded"})
                incomplete_reasons.add("changed-total-byte-limit-exceeded")
                continue
            read_limit = min(_MAX_FINGERPRINT_FILE_BYTES, remaining)
            data, failure = self._read_fingerprint_bytes(relative, max_bytes=read_limit)
            if failure == "deleted":
                file_rows.append({"path": relative, "state": "deleted"})
                continue
            if failure == "byte-limit-exceeded":
                reason = (
                    "changed-total-byte-limit-exceeded"
                    if read_limit < _MAX_FINGERPRINT_FILE_BYTES
                    else "changed-file-byte-limit-exceeded"
                )
                file_rows.append({"path": relative, "state": reason})
                incomplete_reasons.add(reason)
                continue
            if failure is not None:
                file_rows.append({"path": relative, "state": failure})
                incomplete_reasons.add(failure)
                continue
            if data is None:
                raise RuntimeError("fingerprint reader returned neither data nor a failure")
            total_hashed_bytes += len(data)
            file_rows.append(
                {
                    "path": relative,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        if len(changed_files) > _MAX_FINGERPRINT_CHANGED_FILES:
            file_rows.append({"state": "changed-file-overflow", "count": len(changed_files)})
        reasons = tuple(sorted(incomplete_reasons))
        payload = {
            "git_sha": git_sha,
            "index_sha256": index_sha256,
            "status": status,
            "files": file_rows,
            "fingerprint_complete": not reasons,
            "fingerprint_incomplete_reasons": list(reasons),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return (
            f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
            not reasons,
            reasons,
        )

    @contextmanager
    def _git_metadata_cwd(self) -> Iterator[Path]:
        if (
            self.workspace_root_identity is None
            or self.git_dir_identity is None
            or not descriptor_relative_authority_supported()
        ):
            raise RuntimeError("Git metadata inspection requires descriptor authority")
        root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(self.workspace, root_flags)
        child_fd = -1
        try:
            root_stat = os.fstat(root_fd)
            if _identity(root_stat) != self.workspace_root_identity:
                raise RepositorySubjectError("repository workspace changed identity")
            child_fd = os.open(".git", root_flags, dir_fd=root_fd)
            child_stat = os.fstat(child_fd)
            current_child = os.stat(".git", dir_fd=root_fd, follow_symlinks=False)
            if (
                _identity(child_stat) != self.git_dir_identity
                or _identity(current_child) != self.git_dir_identity
            ):
                raise RepositorySubjectError("repository Git metadata changed identity")
            if os.get_inheritable(root_fd) or os.get_inheritable(child_fd):
                raise RuntimeError("Git authority descriptor unexpectedly became inheritable")
            yield _descriptor_path(child_fd, label="Git metadata inspection")
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            os.close(root_fd)

    def _git_worktree_bytes(self, *args: str, max_stdout_bytes: int) -> bytes:
        if args != ("ls-files", "--others", "--exclude-standard", "-z"):
            raise ValueError("unsupported Git worktree metadata command")
        if self.git_dir_identity is None or self.workspace_root_identity is None:
            raise RuntimeError("target workspace is not a direct authorized Git repository")
        self._assert_git_subject_current()
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_LAZY_FETCH": "1",
                },
            )
            try:
                with descriptor_bound_cwd(
                    self.workspace,
                    expected_root_identity=self.workspace_root_identity,
                    label="Git worktree name inspection",
                ) as git_cwd:
                    result = run_bounded_binary_subprocess(
                        [
                            "git",
                            "--git-dir=.git",
                            "--work-tree=.",
                            "-c",
                            "core.fsmonitor=false",
                            "-c",
                            "core.untrackedCache=false",
                            "-c",
                            "core.excludesFile=/dev/null",
                            *args,
                        ],
                        cwd=git_cwd,
                        env=env,
                        timeout_seconds=self.timeout_seconds,
                        max_stdout_bytes=max_stdout_bytes,
                        max_stderr_bytes=_MAX_GIT_EXACT_STDERR_BYTES,
                    )
            except (OSError, RuntimeError, ValueError) as exc:
                raise RepositorySubjectError(
                    "Git worktree subject could not be bound to the authorized workspace"
                ) from exc
        self._assert_git_subject_current()
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git worktree metadata output exceeded bounded capture limit")
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        _raise_if_git_grafts_reported(stderr)
        if result.returncode != 0:
            raise RuntimeError(stderr or f"git worktree metadata command failed: {args}")
        return result.stdout

    @staticmethod
    def _validate_metadata_git_command(args: tuple[str, ...]) -> None:
        if not args:
            raise ValueError("Git metadata command must not be empty")
        safe = False
        if args in {("rev-parse", "HEAD"), ("rev-parse", "--show-object-format")}:
            safe = True
        elif len(args) == 3 and args[:2] == ("rev-parse", "--verify"):
            value = args[2]
            safe = value.endswith("^{commit}") and bool(
                _SAFE_REF.fullmatch(value[: -len("^{commit}")])
            )
        elif args == ("symbolic-ref", "--quiet", "--short", "HEAD"):
            safe = True
        elif (
            len(args) == 3
            and args[0] == "merge-base"
            and all(_HEX_SHA.fullmatch(value) for value in args[1:])
        ):
            safe = True
        elif args == ("ls-files", "--stage", "-z"):
            safe = True
        elif (
            len(args) == 5
            and args[0:4] == ("ls-tree", "-r", "-z", "--full-tree")
            and _HEX_SHA.fullmatch(args[4])
        ):
            safe = True
        elif (
            len(args) == 6
            and args[0:3] == ("ls-tree", "-z", "--full-tree")
            and _HEX_SHA.fullmatch(args[3])
            and args[4] == "--"
            and args[5].startswith(":(literal)")
        ):
            safe = True
        elif (
            len(args) == 3
            and args[0] == "cat-file"
            and args[1] in {"-s", "blob"}
            and _HEX_SHA.fullmatch(args[2])
        ):
            safe = True
        if not safe:
            raise ValueError(f"unsupported Git metadata-only inspection command: {args[0]}")

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        if self.git_dir_identity is None:
            if allow_failure:
                return None
            raise RuntimeError("target workspace is not a direct Git repository")
        self._validate_metadata_git_command(tuple(args))
        self._assert_git_subject_current()
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_LAZY_FETCH": "1",
                },
            )
            with self._git_metadata_cwd() as git_cwd:
                result = run_bounded_subprocess(
                    [
                        "git",
                        "--git-dir=.",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.untrackedCache=false",
                        "-c",
                        "advice.graftFileDeprecated=true",
                        *args,
                    ],
                    cwd=git_cwd,
                    env=env,
                    timeout_seconds=self.timeout_seconds,
                    max_output_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES,
                )
        self._assert_git_subject_current()
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git inspection output exceeded bounded capture limit")
        _raise_if_git_grafts_reported(result.stderr)
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(result.stderr.strip() or f"git command failed: {args}")
        return result.stdout.rstrip("\r\n")

    def _git_bytes(
        self,
        *args: str,
        max_stdout_bytes: int,
        allow_failure: bool = False,
    ) -> bytes | None:
        if self.git_dir_identity is None:
            if allow_failure:
                return None
            raise RuntimeError("target workspace is not a direct Git repository")
        self._validate_metadata_git_command(tuple(args))
        self._assert_git_subject_current()
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_LAZY_FETCH": "1",
                },
            )
            with self._git_metadata_cwd() as git_cwd:
                result = run_bounded_binary_subprocess(
                    [
                        "git",
                        "--git-dir=.",
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.untrackedCache=false",
                        "-c",
                        "advice.graftFileDeprecated=true",
                        *args,
                    ],
                    cwd=git_cwd,
                    env=env,
                    timeout_seconds=self.timeout_seconds,
                    max_stdout_bytes=max_stdout_bytes,
                    max_stderr_bytes=_MAX_GIT_EXACT_STDERR_BYTES,
                )
        self._assert_git_subject_current()
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git exact-byte output exceeded bounded capture limit")
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        _raise_if_git_grafts_reported(stderr)
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(stderr or f"git command failed: {args}")
        return result.stdout
