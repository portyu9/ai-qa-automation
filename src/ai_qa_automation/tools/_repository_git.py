from __future__ import annotations

import os
import re
import stat
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path

from ..fs_observation import ConfinedFileScan
from ._repository_common import (
    _HEX_SHA,
    _MAX_GIT_CONFIG_BYTES,
    _MAX_GIT_EXACT_STDERR_BYTES,
    _MAX_GIT_METADATA_SCAN_ENTRIES,
    _MAX_GIT_TEXT_OUTPUT_BYTES,
    _SAFE_REF,
    RepositorySubjectError,
    raise_if_git_grafts_reported,
)
from .execution_env import (
    BoundedBinarySubprocessResult,
    BoundedSubprocessResult,
    restricted_subprocess_env,
)


class RepositoryGitAuthorityMixin:
    workspace: Path
    timeout_seconds: int
    workspace_root_identity: tuple[int, int] | None
    git_dir_identity: tuple[int, int] | None

    def _pin_directory_identity_adapter(self, root: Path, *, label: str) -> tuple[int, int]:
        raise NotImplementedError

    def _read_bytes_confined_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        raise NotImplementedError

    def _stat_confined_entry_adapter(
        self,
        root: Path,
        relative_path: str | Path,
        *,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> os.stat_result:
        raise NotImplementedError

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
        raise NotImplementedError

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
        raise NotImplementedError

    def _descriptor_bound_child_directory_adapter(
        self,
        root: Path,
        child_name: str,
        *,
        expected_root_identity: tuple[int, int],
        expected_child_identity: tuple[int, int] | None = None,
        label: str,
    ) -> AbstractContextManager[tuple[Path, Path, tuple[int, int]]]:
        raise NotImplementedError

    def _discover_git_dir_identity(self) -> tuple[int, int] | None:
        if self.workspace_root_identity is None:
            return None
        try:
            observed = self._stat_confined_entry_adapter(
                self.workspace,
                ".git",
                label="repository Git metadata directory",
                expected_root_identity=self.workspace_root_identity,
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository Git metadata directory could not be inspected safely"
            ) from exc
        if not stat.S_ISDIR(observed.st_mode):
            raise RepositorySubjectError(
                "repository Git metadata must be one direct no-follow directory"
            )
        return observed.st_dev, observed.st_ino

    def _read_git_metadata_file(self, relative_path: str, *, label: str) -> bytes | None:
        if self.git_dir_identity is None:
            return None
        try:
            return self._read_bytes_confined_adapter(
                self.workspace / ".git",
                relative_path,
                max_bytes=_MAX_GIT_CONFIG_BYTES,
                label=label,
                expected_root_identity=self.git_dir_identity,
            )
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise RepositorySubjectError(f"{label} could not be inspected safely") from exc

    def _assert_git_metadata_safe(self) -> None:
        if self.git_dir_identity is None:
            return
        try:
            scan = self._scan_regular_files_adapter(
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

        for relative, label in (
            ("commondir", "Git common-directory indirection"),
            ("objects/info/alternates", "Git alternate-object indirection"),
            ("objects/info/http-alternates", "Git HTTP alternate-object indirection"),
        ):
            data = self._read_git_metadata_file(relative, label=label)
            if data is not None and (relative == "commondir" or data.strip()):
                raise RepositorySubjectError(
                    "repository Git metadata must not redirect to external common/object storage"
                )

        grafts = self._read_git_metadata_file("info/grafts", label="legacy Git graft metadata")
        if grafts is not None and grafts.strip():
            raise RepositorySubjectError("repository Git metadata must not use legacy grafts")

        include_section = re.compile(r"^\s*\[\s*include(?:if)?(?:\s|\])", re.IGNORECASE)
        for relative, label in (
            ("config", "repository Git config"),
            ("config.worktree", "repository Git worktree config"),
        ):
            config = self._read_git_metadata_file(relative, label=label)
            if config is None:
                continue
            try:
                text = config.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise RepositorySubjectError(f"{label} is not valid UTF-8") from exc
            if any(include_section.search(line) for line in text.splitlines()):
                raise RepositorySubjectError(
                    "repository Git config must not include external configuration"
                )

    def _assert_git_subject_current(self) -> None:
        self._assert_workspace_subject_current()
        if self.git_dir_identity is None:
            return
        current = self._discover_git_dir_identity()
        if current != self.git_dir_identity:
            raise RepositorySubjectError(
                "repository Git metadata changed identity during inspection"
            )
        self._assert_git_metadata_safe()

    def _assert_workspace_subject_current(self) -> None:
        if self.workspace_root_identity is None:
            return
        try:
            current_identity = self._pin_directory_identity_adapter(
                self.workspace,
                label="repository inspection workspace",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "repository workspace subject could not be revalidated"
            ) from exc
        if current_identity != self.workspace_root_identity:
            raise RepositorySubjectError("repository workspace changed identity during inspection")

    @contextmanager
    def _git_subject(self) -> Iterator[tuple[Path, tuple[str, ...], tuple[int, ...]]]:
        if self.workspace_root_identity is None or self.git_dir_identity is None:
            raise RuntimeError("Git inspection requires a direct authorized repository")
        self._assert_git_subject_current()
        try:
            with self._descriptor_bound_child_directory_adapter(
                self.workspace,
                ".git",
                expected_root_identity=self.workspace_root_identity,
                expected_child_identity=self.git_dir_identity,
                label="Git repository inspection",
            ) as (workspace_path, git_dir_path, pass_fds):
                yield (
                    workspace_path,
                    (f"--git-dir={git_dir_path}", f"--work-tree={workspace_path}"),
                    pass_fds,
                )
        except RepositorySubjectError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise RepositorySubjectError(
                "Git repository metadata and worktree could not be bound "
                "to the authorized workspace"
            ) from exc
        finally:
            self._assert_git_subject_current()

    @staticmethod
    def _validate_git_command(args: tuple[str, ...]) -> None:
        if not args:
            raise ValueError("Git inspection command must not be empty")
        safe = False
        if args in {
            ("rev-parse", "HEAD"),
            ("rev-parse", "--show-object-format"),
            ("symbolic-ref", "--quiet", "--short", "HEAD"),
            ("ls-files", "--stage", "-z", "--"),
            ("ls-files", "-v", "-z", "--"),
            ("ls-files", "--others", "--exclude-standard", "-z", "--"),
            (
                "diff-files",
                "--name-only",
                "-z",
                "--no-ext-diff",
                "--no-textconv",
                "--ignore-submodules=all",
                "--",
            ),
        }:
            safe = True
        elif len(args) == 3 and args[:2] == ("rev-parse", "--verify"):
            value = args[2]
            safe = value.endswith("^{commit}") and bool(
                _SAFE_REF.fullmatch(value[: -len("^{commit}")])
            )
        elif (
            (
                len(args) == 3
                and args[0] == "merge-base"
                and all(_HEX_SHA.fullmatch(value) for value in args[1:])
            )
            or (
                len(args) == 5
                and args[:4] == ("ls-tree", "-r", "-z", "--full-tree")
                and _HEX_SHA.fullmatch(args[4])
            )
            or (
                len(args) == 6
                and args[:3] == ("ls-tree", "-z", "--full-tree")
                and _HEX_SHA.fullmatch(args[3])
                and args[4] == "--"
                and args[5].startswith(":(literal)")
            )
            or (
                len(args) == 3
                and args[0] == "cat-file"
                and args[1] in {"-s", "blob"}
                and _HEX_SHA.fullmatch(args[2])
            )
        ):
            safe = True
        if not safe:
            raise ValueError(f"unsupported Git inspection command: {args[0]}")

    def _git(self, *args: str, allow_failure: bool = False) -> str | None:
        if self.git_dir_identity is None:
            if allow_failure:
                return None
            raise RuntimeError("target workspace is not a direct Git repository")
        self._validate_git_command(tuple(args))
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_LAZY_FETCH": "1",
                },
            )
            with self._git_subject() as (git_cwd, git_subject_args, pass_fds):
                result = self._run_bounded_subprocess_adapter(
                    [
                        "git",
                        *git_subject_args,
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.untrackedCache=false",
                        "-c",
                        "core.excludesFile=/dev/null",
                        "-c",
                        "core.filemode=true",
                        "-c",
                        "core.ignoreStat=false",
                        "-c",
                        "core.trustctime=true",
                        "-c",
                        "core.checkStat=default",
                        "-c",
                        "advice.graftFileDeprecated=true",
                        *args,
                    ],
                    cwd=git_cwd,
                    env=env,
                    timeout_seconds=self.timeout_seconds,
                    max_output_bytes=_MAX_GIT_TEXT_OUTPUT_BYTES,
                    pass_fds=pass_fds,
                )
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git inspection output exceeded bounded capture limit")
        raise_if_git_grafts_reported(result.stderr)
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
        self._validate_git_command(tuple(args))
        with tempfile.TemporaryDirectory(prefix="aiqa-git-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_NO_LAZY_FETCH": "1",
                },
            )
            with self._git_subject() as (git_cwd, git_subject_args, pass_fds):
                result = self._run_bounded_binary_subprocess_adapter(
                    [
                        "git",
                        *git_subject_args,
                        "-c",
                        "core.fsmonitor=false",
                        "-c",
                        "core.untrackedCache=false",
                        "-c",
                        "core.excludesFile=/dev/null",
                        "-c",
                        "core.filemode=true",
                        "-c",
                        "core.ignoreStat=false",
                        "-c",
                        "core.trustctime=true",
                        "-c",
                        "core.checkStat=default",
                        "-c",
                        "advice.graftFileDeprecated=true",
                        *args,
                    ],
                    cwd=git_cwd,
                    env=env,
                    timeout_seconds=self.timeout_seconds,
                    max_stdout_bytes=max_stdout_bytes,
                    max_stderr_bytes=_MAX_GIT_EXACT_STDERR_BYTES,
                    pass_fds=pass_fds,
                )
        if result.timed_out:
            raise RuntimeError(f"git command exceeded {self.timeout_seconds}s inspection budget")
        if result.stdout_truncated or result.stderr_truncated:
            raise RuntimeError("git exact-byte output exceeded bounded capture limit")
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise_if_git_grafts_reported(stderr)
        if result.returncode != 0:
            if allow_failure:
                return None
            raise RuntimeError(stderr or f"git command failed: {args}")
        return result.stdout
