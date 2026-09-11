from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from ..fs_authority import descriptor_relative_authority_supported
from ..tools.subprocess_subject import active_workspace_authority
from .workspace_lease import WorkspaceBusyError


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


@contextmanager
def recovery_workspace_observation_guard(workspace: Path) -> Iterator[tuple[int, int]]:
    """Hold read-side workspace authority while persisted recovery truth is inspected.

    Live agent runs hold an exclusive flock on this same workspace inode for their
    full lease lifetime. Recovery takes a shared nonblocking flock, so it cannot
    inspect concurrently with an authorized writer and a new writer cannot start
    until the recovery observation completes.
    """

    if not descriptor_relative_authority_supported():
        raise RuntimeError(
            "recovery workspace observation requires descriptor-relative filesystem authority"
        )

    workspace = workspace.expanduser().absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(workspace, flags)
    except OSError as exc:
        raise OSError("recovery workspace could not be opened safely") from exc

    locked = False
    try:
        opened = os.fstat(fd)
        current = workspace.stat(follow_symlinks=False)
        identity = _identity(opened)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(current.st_mode)
            or _identity(current) != identity
        ):
            raise OSError("recovery workspace changed identity before observation lock")
        if active_workspace_authority(workspace) is not None:
            raise WorkspaceBusyError("target workspace is already leased by a live run")

        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - POSIX capability guard
            raise RuntimeError("recovery workspace locking is unavailable") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            raise WorkspaceBusyError("target workspace is already leased by a live run") from exc
        locked = True

        current = workspace.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or _identity(current) != identity:
            raise OSError("recovery workspace changed identity during observation lock")
        if active_workspace_authority(workspace) is not None:
            raise WorkspaceBusyError("target workspace acquired live process authority")
        yield identity

        current = workspace.stat(follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or _identity(current) != identity:
            raise OSError("recovery workspace changed identity during observation")
    finally:
        if locked:
            with suppress(OSError):
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(fd)
