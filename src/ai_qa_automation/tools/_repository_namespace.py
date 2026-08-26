from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

from ..fs_observation import ConfinedFileScan
from ._repository_common import _MAX_GIT_PATHS, RepositorySubjectError
from ._repository_worktree import RepositoryWorktreeMixin

_MetadataSignature = tuple[int, int, int, int, int, int]
_NamespaceObservation = tuple[tuple[str, _MetadataSignature], ...]
_UNTRACKED_PATH_LIST = ("ls-files", "--others", "--exclude-standard", "-z", "--")


class RepositoryNamespaceAuthorityMixin(RepositoryWorktreeMixin):
    """Bind Git untracked-path enumeration to a stable worktree directory namespace."""

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

    @staticmethod
    def _directory_metadata_signature(value: os.stat_result) -> _MetadataSignature:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    def _workspace_root_metadata_signature(self) -> _MetadataSignature:
        expected = self.workspace_root_identity
        if expected is None:
            raise RuntimeError("worktree namespace observation requires an authorized workspace")

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            directory_fd = os.open(self.workspace, directory_flags)
        except OSError as exc:
            raise RepositorySubjectError(
                "repository worktree root could not be opened through no-follow authority"
            ) from exc
        try:
            opened = os.fstat(directory_fd)
            current = self.workspace.stat(follow_symlinks=False)
        except OSError as exc:
            raise RepositorySubjectError(
                "repository worktree root could not be observed safely"
            ) from exc
        finally:
            os.close(directory_fd)

        opened_identity = (opened.st_dev, opened.st_ino)
        current_identity = (current.st_dev, current.st_ino)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or opened_identity != expected
            or current_identity != expected
        ):
            raise RepositorySubjectError(
                "repository worktree root changed identity during namespace observation"
            )
        return self._directory_metadata_signature(opened)

    @staticmethod
    def _namespace_parent_paths(scan: ConfinedFileScan) -> tuple[PurePosixPath, ...]:
        parents: set[PurePosixPath] = set()
        subjects = [item.path for item in scan.files]
        subjects.extend(scan.unsafe_paths)
        subjects.extend(scan.unreadable_paths)
        for subject in subjects:
            parent = subject.parent
            while parent.parts:
                parents.add(parent)
                parent = parent.parent
        return tuple(sorted(parents, key=PurePosixPath.as_posix))

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
            ("", self._workspace_root_metadata_signature())
        ]
        for relative in self._namespace_parent_paths(scan):
            path = relative.as_posix()
            try:
                observed = self._stat_confined_entry_adapter(
                    self.workspace,
                    path,
                    label=f"repository worktree namespace directory {path}",
                    expected_root_identity=expected,
                )
            except (OSError, ValueError) as exc:
                raise RuntimeError(
                    "repository worktree namespace directory could not be observed safely"
                ) from exc
            if not stat.S_ISDIR(observed.st_mode):
                raise RuntimeError("repository worktree namespace parent is not a directory")
            rows.append((path, self._directory_metadata_signature(observed)))
        return tuple(rows)

    def _git_path_list(self, *args: str) -> tuple[str, ...]:
        if args != _UNTRACKED_PATH_LIST:
            return super()._git_path_list(*args)

        before = self._worktree_namespace_observation()
        paths = super()._git_path_list(*args)
        after = self._worktree_namespace_observation()
        if before != after:
            raise RuntimeError("repository worktree namespace changed during untracked enumeration")
        return paths
