from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from pathlib import Path

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
    stat_confined_entry,
)
from ..fs_observation import ConfinedFileScan, scan_regular_files_confined
from ._repository_common import (
    _GIT_MODE,
    _HEX_SHA,
    _MAX_GIT_EXACT_STDOUT_BYTES,
    _MAX_GIT_PATHS,
    RepositoryChangeSet,
    RepositorySnapshot,
    RepositorySubjectError,
)
from ._repository_git import RepositoryGitAuthorityMixin
from ._repository_worktree import RepositoryWorktreeMixin
from .execution_env import (
    BoundedBinarySubprocessResult,
    BoundedSubprocessResult,
    run_bounded_binary_subprocess,
    run_bounded_subprocess,
)
from .subprocess_subject import (
    active_workspace_authority,
    descriptor_bound_child_directory,
)


class RepositoryInspector(RepositoryGitAuthorityMixin, RepositoryWorktreeMixin):
    """Read-only repository inspection with explicit metadata/worktree authority layers."""

    # Ambient authority enters only through these adapters. Keeping them in this public
    # module preserves the existing adversarial monkeypatch seams while private layers
    # remain deterministic consumers of explicitly supplied capabilities.
    def _pin_directory_identity_adapter(self, root: Path, *, label: str) -> tuple[int, int]:
        return pin_directory_identity(root, label=label)

    def _read_bytes_confined_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        return read_bytes_confined(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    def _stat_confined_entry_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> os.stat_result:
        return stat_confined_entry(
            root,
            relative_path,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    def _scan_regular_files_adapter(
        self,
        root: Path,
        *,
        max_entries: int,
        ignored_names: set[str] | frozenset[str] = frozenset(),
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> ConfinedFileScan:
        return scan_regular_files_confined(
            root,
            max_entries=max_entries,
            ignored_names=ignored_names,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    def _run_bounded_subprocess_adapter(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedSubprocessResult:
        return run_bounded_subprocess(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            pass_fds=pass_fds,
        )

    def _run_bounded_binary_subprocess_adapter(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_stdout_bytes: int = 2_000_000,
        max_stderr_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedBinarySubprocessResult:
        return run_bounded_binary_subprocess(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            pass_fds=pass_fds,
        )

    def _descriptor_bound_child_directory_adapter(
        self,
        root: Path,
        child_name: str,
        *,
        expected_root_identity: tuple[int, int],
        expected_child_identity: tuple[int, int] | None = None,
        label: str,
    ) -> AbstractContextManager[tuple[Path, Path, tuple[int, int]]]:
        return descriptor_bound_child_directory(
            root,
            child_name,
            expected_root_identity=expected_root_identity,
            expected_child_identity=expected_child_identity,
            label=label,
        )

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

        # Resolving after lease acquisition could follow a replacement symlink before
        # the active lease-authority lookup and silently change the repository subject.
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
        if descriptor_relative_authority_supported():
            try:
                current_identity = pin_directory_identity(
                    self.workspace,
                    label="repository inspection workspace",
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
            self.git_dir_identity = self._discover_git_dir_identity()
            if self.git_dir_identity is not None:
                self._assert_git_metadata_safe()
        else:
            raise RepositorySubjectError(
                "repository inspection requires descriptor-bound filesystem authority"
            )

    def snapshot(self) -> RepositorySnapshot:
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
        try:
            sha = self._git("rev-parse", "HEAD", allow_failure=True)
            if sha is not None:
                sha = self._verify_exact_commit_oid(sha)
            branch = self._git("symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True)
            object_format = self._git("rev-parse", "--show-object-format")
            if object_format not in {"sha1", "sha256"}:
                raise RuntimeError("Git returned an unsupported object format")
            status, changed, index_digest, observation_reasons = self._worktree_status(
                sha, object_format
            )
            final_sha = self._git("rev-parse", "HEAD", allow_failure=True)
            if final_sha != sha:
                raise RuntimeError("Git HEAD changed during repository inspection")
            if hashlib.sha256(self._read_index_bytes()).hexdigest() != index_digest:
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
        fingerprint, complete, incomplete_reasons = self._fingerprint(
            sha,
            status,
            changed,
            index_digest=index_digest,
            initial_incomplete_reasons=observation_reasons,
        )
        self._assert_git_subject_current()
        try:
            post_fingerprint_sha = self._git("rev-parse", "HEAD", allow_failure=True)
            post_fingerprint_index = hashlib.sha256(self._read_index_bytes()).hexdigest()
        except RuntimeError:
            return self._incomplete_snapshot("git-inspection-incomplete")
        if post_fingerprint_sha != sha or post_fingerprint_index != index_digest:
            return self._incomplete_snapshot("repository-state-changed-during-inspection")
        return RepositorySnapshot(
            workspace=str(self.workspace),
            git_sha=sha or None,
            branch=branch or None,
            status=status,
            changed_files=changed,
            fingerprint=fingerprint,
            fingerprint_complete=complete,
            fingerprint_incomplete_reasons=incomplete_reasons,
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

    def _verify_exact_commit_oid(self, object_id: str) -> str:
        if not _HEX_SHA.fullmatch(object_id):
            raise RuntimeError("Git returned an invalid commit object id")
        resolved = self._git("rev-parse", "--verify", f"{object_id}^{{commit}}")
        if (
            resolved is None
            or not _HEX_SHA.fullmatch(resolved)
            or resolved.lower() != object_id.lower()
        ):
            raise RuntimeError("Git commit subject does not match its requested object id")
        return resolved.lower()

    def change_set(self, base_ref: str) -> RepositoryChangeSet:
        """Resolve an immutable baseline and union committed/worktree change evidence."""
        safe_ref = self._validate_ref(base_ref)
        head = self._git("rev-parse", "HEAD")
        if head is None:
            raise RuntimeError("target workspace is not a Git repository")
        head = self._verify_exact_commit_oid(head)
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

    def _tree_entries_at(self, commit_sha: str) -> dict[str, tuple[str, str]]:
        raw = self._git_bytes(
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit_sha,
            max_stdout_bytes=_MAX_GIT_EXACT_STDOUT_BYTES,
        )
        if raw is None:
            raise RuntimeError("Git tree enumeration returned no result")
        entries: dict[str, tuple[str, str]] = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, raw_path = record.partition(b"\t")
            if not separator:
                raise RuntimeError("Git returned a malformed tree entry")
            try:
                fields = metadata.decode("ascii").split()
                path = self._validate_relative_path(raw_path.decode("utf-8", errors="strict"))
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
                or len(entries) >= _MAX_GIT_PATHS
            ):
                raise RuntimeError("Git tree enumeration exceeded bounds or was malformed")
            entries[path] = (mode, object_id.lower())
        return entries

    def _blob_oid_at(self, commit_sha: str, path: str) -> str | None:
        """Resolve one literal path at an immutable commit to its exact blob object ID."""
        raw = self._git(
            "ls-tree",
            "-z",
            "--full-tree",
            commit_sha,
            "--",
            f":(literal){path}",
        )
        if raw is None:  # pragma: no cover - _git without allow_failure raises instead
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
        return object_id

    def read_file_at(
        self, commit_sha: str, relative_path: str, *, max_bytes: int = 2_000_000
    ) -> bytes:
        """Read one bounded tracked blob from an immutable commit without checkout."""
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
        commit_sha = self._verify_exact_commit_oid(commit_sha)
        path = self._validate_relative_path(relative_path)
        blob_oid = self._blob_oid_at(commit_sha, path)
        if blob_oid is None:
            raise FileNotFoundError(path)

        object_format = self._git("rev-parse", "--show-object-format")
        if object_format not in {"sha1", "sha256"}:
            raise RuntimeError("Git returned an unsupported object format")
        size_text = self._git("cat-file", "-s", blob_oid)
        if size_text is None:  # pragma: no cover - _git without allow_failure raises instead
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
            "cat-file",
            "blob",
            blob_oid,
            max_stdout_bytes=max(1, size),
        )
        if result is None:  # pragma: no cover - _git_bytes without allow_failure raises instead
            raise RuntimeError("Git blob read returned no result")
        if len(result) != size:
            raise RuntimeError(
                "Git returned baseline bytes inconsistent with preflight object size"
            )
        if self._raw_blob_oid(result, object_format) != blob_oid.lower():
            raise RuntimeError("Git blob content does not match its content-addressed object id")
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