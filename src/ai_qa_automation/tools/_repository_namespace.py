from __future__ import annotations

from pathlib import Path
from typing import cast

from ..fs_observation import ConfinedFileScan
from ._repository_common import (
    _MAX_GIT_METADATA_SCAN_ENTRIES,
    _MAX_GIT_PATHS,
    RepositorySubjectError,
)
from ._repository_git import RepositoryGitAuthorityMixin
from ._repository_worktree import RepositoryWorktreeMixin

_MetadataSignature = tuple[int, int, int, int, int, int]
_NamespaceObservation = tuple[tuple[str, _MetadataSignature], ...]
_GitMetadataObservation = tuple[tuple[str, _MetadataSignature], ...]
_UNTRACKED_PATH_LIST = ("ls-files", "--others", "--exclude-standard", "-z", "--")
_NESTED_GIT_INDIRECTION_PATHS = {
    ("commondir",),
    ("objects", "info", "alternates"),
    ("objects", "info", "http-alternates"),
}


class RepositoryNamespaceAuthorityMixin:
    """Bind Git reads to stable worktree and repository filesystem authority."""

    workspace: Path
    workspace_root_identity: tuple[int, int] | None
    git_dir_identity: tuple[int, int] | None

    def _scan_regular_files_adapter(
        self,
        root: Path,
        *,
        max_entries: int,
        ignored_names: set[str] | frozenset[str] = frozenset(),
        ignored_root_names: set[str] | frozenset[str] = frozenset(),
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> ConfinedFileScan:
        raise NotImplementedError

    @staticmethod
    def _nested_git_relative_parts(path: Path) -> tuple[str, ...] | None:
        parts = path.parts
        try:
            marker = parts.index(".git")
        except ValueError:
            return None
        if marker == 0:
            return None
        return parts[marker + 1 :]

    def _worktree_namespace_observation(self) -> _NamespaceObservation:
        expected = self.workspace_root_identity
        if expected is None:
            raise RuntimeError("worktree namespace observation requires an authorized workspace")
        try:
            scan = self._scan_regular_files_adapter(
                self.workspace,
                max_entries=_MAX_GIT_PATHS,
                ignored_root_names={".git"},
                label="repository worktree namespace",
                expected_root_identity=expected,
            )
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError(
                "repository worktree namespace could not be observed safely"
            ) from exc

        if scan.resource_truncated:
            raise RuntimeError("repository worktree namespace exceeded its bounded scan budget")
        if scan.unreadable_paths:
            raise RuntimeError("repository worktree namespace contains unreadable paths")

        nested_gitfiles = tuple(item.path for item in scan.files if item.path.name == ".git")
        if nested_gitfiles:
            raise RepositorySubjectError(
                "nested Git gitfile authority is not supported by repository inspection"
            )
        if any(".git" in path.parts for path in scan.unsafe_paths):
            raise RepositorySubjectError(
                "nested Git metadata contains unsupported filesystem aliases"
            )
        for item in scan.files:
            nested_relative = self._nested_git_relative_parts(Path(item.path.as_posix()))
            if nested_relative in _NESTED_GIT_INDIRECTION_PATHS:
                raise RepositorySubjectError(
                    "nested Git metadata contains unsupported external indirection"
                )

        rows: list[tuple[str, _MetadataSignature]] = [
            (f"dir:{item.path.as_posix()}", item.metadata_signature) for item in scan.directories
        ]
        rows.extend(
            (f"file:{item.path.as_posix()}", item.metadata_signature) for item in scan.files
        )
        return tuple(sorted(rows))

    def _git_metadata_observation(self) -> _GitMetadataObservation:
        expected = self.git_dir_identity
        if expected is None:
            raise RuntimeError("Git metadata observation requires a direct repository")
        try:
            scan = self._scan_regular_files_adapter(
                self.workspace / ".git",
                max_entries=_MAX_GIT_METADATA_SCAN_ENTRIES,
                label="repository Git metadata authority",
                expected_root_identity=expected,
            )
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository Git metadata authority could not be observed safely"
            ) from exc
        if scan.truncated or scan.unsafe_paths or scan.unreadable_paths:
            raise RepositorySubjectError(
                "repository Git metadata authority is incomplete or contains unsafe entries"
            )

        rows: list[tuple[str, _MetadataSignature]] = [
            (f"dir:{item.path.as_posix()}", item.metadata_signature) for item in scan.directories
        ]
        rows.extend(
            (f"file:{item.path.as_posix()}", item.metadata_signature) for item in scan.files
        )
        return tuple(sorted(rows))

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        authority = cast(RepositoryGitAuthorityMixin, self)
        before = self._git_metadata_observation()
        original_error: Exception | None = None
        try:
            result = RepositoryGitAuthorityMixin._git(
                authority,
                *args,
                allow_failure=allow_failure,
            )
        except Exception as exc:
            original_error = exc
            raise
        finally:
            try:
                after = self._git_metadata_observation()
            except Exception:
                if original_error is None:
                    raise
            else:
                if before != after and original_error is None:
                    raise RuntimeError("repository Git metadata changed during Git inspection")
        return result

    def _git_bytes(
        self,
        *args: str,
        max_stdout_bytes: int,
        allow_failure: bool = False,
    ) -> bytes | None:
        authority = cast(RepositoryGitAuthorityMixin, self)
        before = self._git_metadata_observation()
        original_error: Exception | None = None
        try:
            result = RepositoryGitAuthorityMixin._git_bytes(
                authority,
                *args,
                max_stdout_bytes=max_stdout_bytes,
                allow_failure=allow_failure,
            )
        except Exception as exc:
            original_error = exc
            raise
        finally:
            try:
                after = self._git_metadata_observation()
            except Exception:
                if original_error is None:
                    raise
            else:
                if before != after and original_error is None:
                    raise RuntimeError("repository Git metadata changed during Git inspection")
        return result

    def _git_path_list(self, *args: str) -> tuple[str, ...]:
        worktree = cast(RepositoryWorktreeMixin, self)
        if args != _UNTRACKED_PATH_LIST:
            return RepositoryWorktreeMixin._git_path_list(worktree, *args)

        before = self._worktree_namespace_observation()
        paths = RepositoryWorktreeMixin._git_path_list(worktree, *args)
        after = self._worktree_namespace_observation()
        if before != after:
            raise RuntimeError("repository worktree namespace changed during untracked enumeration")
        return paths
