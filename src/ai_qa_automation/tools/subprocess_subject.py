from __future__ import annotations

import errno
import os
import stat
from _thread import RLock
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..fs_authority import descriptor_relative_authority_supported

_DESCRIPTOR_PATH_ROOTS = (Path("/proc/self/fd"), Path("/dev/fd"))
_ACTIVE_WORKSPACE_AUTHORITIES_LOCK = RLock()
_ACTIVE_WORKSPACE_AUTHORITIES: dict[str, tuple[tuple[int, int], str]] = {}


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _authority_key(root: Path) -> str:
    return str(root.expanduser().absolute())


def bind_active_workspace_authority(
    root: Path,
    identity: tuple[int, int] | None,
    *,
    owner: str,
) -> None:
    """Publish one process-local mirror of the currently held workspace lease authority."""

    if identity is None:
        return
    key = _authority_key(root)
    candidate = (identity, owner)
    with _ACTIVE_WORKSPACE_AUTHORITIES_LOCK:
        existing = _ACTIVE_WORKSPACE_AUTHORITIES.get(key)
        if existing is not None and existing != candidate:
            raise RuntimeError("workspace already has a conflicting active lease authority")
        _ACTIVE_WORKSPACE_AUTHORITIES[key] = candidate


def active_workspace_authority(root: Path) -> tuple[int, int] | None:
    """Return the root identity published by the live workspace lease, if one exists."""

    with _ACTIVE_WORKSPACE_AUTHORITIES_LOCK:
        authority = _ACTIVE_WORKSPACE_AUTHORITIES.get(_authority_key(root))
        return authority[0] if authority is not None else None


def clear_active_workspace_authority(
    root: Path,
    identity: tuple[int, int] | None,
    *,
    owner: str,
) -> bool:
    """Clear only the exact active lease authority owned by this lease instance."""

    if identity is None:
        return True
    key = _authority_key(root)
    with _ACTIVE_WORKSPACE_AUTHORITIES_LOCK:
        existing = _ACTIVE_WORKSPACE_AUTHORITIES.get(key)
        if existing is None:
            return True
        if existing != (identity, owner):
            return False
        del _ACTIVE_WORKSPACE_AUTHORITIES[key]
        return True


def _descriptor_path(directory_fd: int, *, label: str) -> Path:
    opened = os.fstat(directory_fd)
    opened_identity = _identity(opened)
    if not stat.S_ISDIR(opened.st_mode):
        raise ValueError(f"{label} descriptor does not reference a directory")

    for root in _DESCRIPTOR_PATH_ROOTS:
        candidate = root / str(directory_fd)
        try:
            observed = candidate.stat()
        except OSError:
            continue
        if stat.S_ISDIR(observed.st_mode) and _identity(observed) == opened_identity:
            return candidate
    raise RuntimeError(f"{label} requires a descriptor-backed directory path")


@contextmanager
def descriptor_bound_cwd(
    root: Path,
    *,
    expected_root_identity: tuple[int, int],
    label: str,
) -> Iterator[Path]:
    """Yield a child-process cwd path anchored to one already-authorized directory identity.

    The parent keeps a non-inheritable directory descriptor open while ``subprocess`` performs
    its pre-exec ``chdir`` through ``/proc/self/fd`` or ``/dev/fd``. The descriptor therefore
    anchors the child to the authorized directory even if the pathname is replaced after this
    check, while normal close-on-exec semantics prevent the descriptor authority from surviving
    into the executed program.
    """

    if not descriptor_relative_authority_supported():
        raise RuntimeError(f"{label} requires descriptor-relative no-follow filesystem authority")

    root = root.expanduser().absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(root, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ValueError(f"{label} root became a symlink or non-directory") from exc
        raise

    try:
        opened = os.fstat(directory_fd)
        opened_identity = _identity(opened)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError(f"{label} root is not a directory")
        if opened_identity != expected_root_identity:
            raise ValueError(f"{label} root changed identity since authorization")
        if os.get_inheritable(directory_fd):
            raise RuntimeError(f"{label} directory descriptor unexpectedly became inheritable")
        yield _descriptor_path(directory_fd, label=label)
    finally:
        os.close(directory_fd)
