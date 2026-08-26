from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .fs_authority import descriptor_relative_authority_supported

_MAX_DIRECTORY_DEPTH = 128


@dataclass(frozen=True)
class ObservedRegularFile:
    path: PurePosixPath
    size: int


@dataclass(frozen=True)
class ConfinedFileScan:
    files: tuple[ObservedRegularFile, ...]
    observed_entries: int
    truncated: bool
    unsafe_paths: tuple[PurePosixPath, ...]
    unreadable_paths: tuple[PurePosixPath, ...]
    root_identity: tuple[int, int]


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def _validated_ignored_names(ignored_names: set[str] | frozenset[str]) -> frozenset[str]:
    normalized: set[str] = set()
    for raw in ignored_names:
        if not isinstance(raw, str) or not raw or raw in {".", ".."}:
            raise ValueError("ignored_names must contain direct non-empty entry names")
        if Path(raw).name != raw:
            raise ValueError("ignored_names must contain direct entry names")
        normalized.add(raw)
    return frozenset(normalized)


def scan_regular_files_confined(
    root: Path,
    *,
    max_entries: int,
    ignored_names: set[str] | frozenset[str] = frozenset(),
    label: str,
    expected_root_identity: tuple[int, int] | None = None,
) -> ConfinedFileScan:
    """Enumerate regular files below ``root`` without following filesystem aliases.

    Enumeration is descriptor-relative and budgets every directory entry observed.
    Each directory is identity- and signature-checked before/after traversal. A
    directory that would exceed the entry budget is not partially published into
    ``files``; the result is marked truncated instead. Recursive descent is capped
    at a hard directory depth so entry-bounded scans cannot exhaust call-stack or
    ancestor-descriptor resources.
    """

    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
        raise ValueError("max_entries must be a positive integer")
    if not isinstance(label, str) or not label.strip():
        raise ValueError("label must be a non-empty string")
    ignored = _validated_ignored_names(ignored_names)
    if not descriptor_relative_authority_supported() or os.scandir not in os.supports_fd:
        raise RuntimeError(
            f"{label} requires descriptor-relative no-follow directory enumeration on this platform"
        )

    root = root.expanduser().absolute()
    if root.is_symlink():
        raise ValueError(f"{label} root is a symlink and has ambiguous ownership")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        root_fd = os.open(root, directory_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} root became a symlink during scan startup") from exc
        raise

    files: list[ObservedRegularFile] = []
    unsafe: list[PurePosixPath] = []
    unreadable: list[PurePosixPath] = []
    observed_entries = 0
    truncated = False
    visited_directories: set[tuple[int, int]] = set()

    def visit(directory_fd: int, relative_parent: PurePosixPath, depth: int) -> bool:
        nonlocal observed_entries, truncated

        opened_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise ValueError(f"{label} encountered a non-directory traversal descriptor")
        directory_identity = _identity(opened_directory)
        if directory_identity in visited_directories:
            raise ValueError(f"{label} encountered a repeated directory identity")
        visited_directories.add(directory_identity)
        initial_signature = _directory_signature(opened_directory)

        names: list[str] = []
        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                f"{label} requires descriptor-based directory enumeration on this platform"
            ) from exc

        budget_exhausted = False
        with entries:
            for entry in entries:
                observed_entries += 1
                name = entry.name
                if not isinstance(name, str) or not name or name in {".", ".."}:
                    raise ValueError(f"{label} encountered an invalid directory entry name")
                if Path(name).name != name:
                    raise ValueError(f"{label} encountered a non-direct directory entry name")
                names.append(name)
                if observed_entries >= max_entries:
                    truncated = True
                    budget_exhausted = True
                    break

        if budget_exhausted:
            if _directory_signature(os.fstat(directory_fd)) != initial_signature:
                raise ValueError(f"{label} directory changed during traversal")
            return False

        for name in sorted(names):
            relative = relative_parent / name
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError:
                unreadable.append(relative)
                continue

            if stat.S_ISLNK(current.st_mode):
                unsafe.append(relative)
                continue
            if stat.S_ISREG(current.st_mode):
                files.append(ObservedRegularFile(path=relative, size=current.st_size))
                continue
            if not stat.S_ISDIR(current.st_mode):
                unsafe.append(relative)
                continue
            if name in ignored:
                continue
            if depth >= _MAX_DIRECTORY_DEPTH:
                truncated = True
                continue

            try:
                child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    unsafe.append(relative)
                else:
                    unreadable.append(relative)
                continue
            try:
                opened_child = os.fstat(child_fd)
                current_child = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_child.st_mode)
                    or not stat.S_ISDIR(current_child.st_mode)
                    or _identity(opened_child) != _identity(current_child)
                ):
                    raise ValueError(f"{label} directory changed identity during traversal")
                child_complete = visit(child_fd, relative, depth + 1)
                final_current_child = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if not stat.S_ISDIR(final_current_child.st_mode) or _identity(
                    os.fstat(child_fd)
                ) != _identity(final_current_child):
                    raise ValueError(f"{label} directory changed identity during traversal")
                if not child_complete:
                    if _directory_signature(os.fstat(directory_fd)) != initial_signature:
                        raise ValueError(f"{label} directory changed during traversal")
                    return False
            finally:
                os.close(child_fd)

        if _directory_signature(os.fstat(directory_fd)) != initial_signature:
            raise ValueError(f"{label} directory changed during traversal")
        return True

    try:
        opened_root = os.fstat(root_fd)
        current_root = root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or not stat.S_ISDIR(current_root.st_mode)
            or _identity(opened_root) != _identity(current_root)
        ):
            raise ValueError(f"{label} root changed identity during scan startup")
        root_identity = _identity(opened_root)
        if expected_root_identity is not None and root_identity != expected_root_identity:
            raise ValueError(f"{label} root changed identity since authorization")

        visit(root_fd, PurePosixPath(), 0)

        final_opened_root = os.fstat(root_fd)
        try:
            final_current_root = root.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"{label} root changed identity during traversal") from exc
        if (
            not stat.S_ISDIR(final_current_root.st_mode)
            or _identity(final_opened_root) != root_identity
            or _identity(final_current_root) != root_identity
        ):
            raise ValueError(f"{label} root changed identity during traversal")
    finally:
        os.close(root_fd)

    return ConfinedFileScan(
        files=tuple(sorted(files, key=lambda item: item.path.as_posix())),
        observed_entries=observed_entries,
        truncated=truncated,
        unsafe_paths=tuple(sorted(unsafe, key=PurePosixPath.as_posix)),
        unreadable_paths=tuple(sorted(unreadable, key=PurePosixPath.as_posix)),
        root_identity=root_identity,
    )
