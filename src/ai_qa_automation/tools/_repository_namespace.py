from __future__ import annotations

from pathlib import Path
from typing import cast

from ..fs_observation import ConfinedFileScan
from ._repository_common import _MAX_GIT_PATHS, RepositorySubjectError
from ._repository_worktree import RepositoryWorktreeMixin

_MetadataSignature = tuple[int, int, int, int, int, int]
_NamespaceObservation = tuple[tuple[str, _MetadataSignature], ...]
_UNTRACKED_PATH_LIST = ("ls-files", "--others", "--exclude-standard", "-z", "--")


class RepositoryNamespaceAuthorityMixin:
    """Bind Git untracked-path enumeration to stable worktree namespace authority."""

    workspace: Path
    workspace_root_identity: tuple[int, int] | None

    def _scan_regular_files_adapter(
        self,
        root: Path,
        *,
        max_entries: int,
        ignored_names: set[str] | frozenset[str] = frozenset(),
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> ConfinedFileScan:
        raise NotImplementedError

    def _worktree_namespace_observation(self) -> _NamespaceObservation:
        expected = self.workspace_root_identity
        if expected is None:
            raise RuntimeError("worktree namespace observation requires an authorized workspace")
        try:
            scan = self._scan_regular_files_adapter(
                self.workspace,
                max_entries=_MAX_GIT_PATHS,
                ignored_names={".git"},
                label="repository worktree namespace",
                expected_root_identity=expected,
            )
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError("repository worktree namespace could not be observed safely") from exc

        if scan.resource_truncated:
            raise RuntimeError("repository worktree namespace exceeded its bounded scan budget")
        if scan.unreadable_paths:
            raise RuntimeError("repository worktree namespace contains unreadable paths")

        rows: list[tuple[str, _MetadataSignature]] = [
            (f"dir:{item.path.as_posix()}", item.metadata_signature)
            for item in scan.directories
        ]
        rows.extend(
            (f"ignore:{item.path.as_posix()}", item.metadata_signature)
            for item in scan.files
            if item.path.name == ".gitignore"
        )
        return tuple(sorted(rows))

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
