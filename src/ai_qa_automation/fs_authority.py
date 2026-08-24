from __future__ import annotations

import errno
import os
import stat
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator
from uuid import uuid4

_READ_CHUNK_BYTES = 1024 * 1024


def descriptor_relative_authority_supported() -> bool:
    """Return whether this platform can pin mutation authority to directory descriptors."""

    return bool(
        os.name != "nt"
        and getattr(os, "O_DIRECTORY", 0)
        and getattr(os, "O_NOFOLLOW", 0)
        and all(
            operation in os.supports_dir_fd
            for operation in (os.open, os.stat, os.mkdir, os.unlink, os.link, os.rename)
        )
    )


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stable_file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _relative_parts(relative_path: str | Path, *, label: str) -> tuple[tuple[str, ...], str]:
    requested = Path(relative_path)
    if requested.is_absolute() or ".." in requested.parts:
        raise ValueError(f"{label} escapes its trusted root")
    parts = tuple(part for part in requested.parts if part not in {"", "."})
    if not parts:
        raise ValueError(f"{label} must name a file below its trusted root")
    return parts[:-1], parts[-1]


@contextmanager
def _open_confined_parent(
    root: Path,
    relative_path: str | Path,
    *,
    create_parents: bool,
    label: str,
) -> Iterator[tuple[int, str]]:
    """Pin the parent of a relative file path without following workspace symlinks."""

    if not descriptor_relative_authority_supported():
        raise RuntimeError(
            f"{label} requires descriptor-relative no-follow filesystem authority on this platform"
        )

    parent_parts, name = _relative_parts(relative_path, label=label)
    root = root.expanduser().absolute()
    if root.is_symlink():
        raise ValueError(f"{label} trusted root is a symlink and has ambiguous ownership")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        current_fd = os.open(root, directory_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} trusted root became a symlink") from exc
        raise

    try:
        opened_root = os.fstat(current_fd)
        current_root = root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_root.st_mode)
            or not stat.S_ISDIR(current_root.st_mode)
            or _identity(opened_root) != _identity(current_root)
        ):
            raise ValueError(f"{label} trusted root changed identity during authority pinning")

        for part in parent_parts:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=current_fd)
            except FileNotFoundError:
                if not create_parents:
                    raise
                os.mkdir(part, 0o755, dir_fd=current_fd)
                os.fsync(current_fd)
                child_fd = os.open(part, directory_flags, dir_fd=current_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise ValueError(f"{label} contains a symlinked parent component") from exc
                raise

            try:
                opened_child = os.fstat(child_fd)
                current_child = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_child.st_mode)
                    or not stat.S_ISDIR(current_child.st_mode)
                    or _identity(opened_child) != _identity(current_child)
                ):
                    raise ValueError(f"{label} parent changed identity during authority pinning")
            except Exception:
                os.close(child_fd)
                raise

            os.close(current_fd)
            current_fd = child_fd

        yield current_fd, name
    finally:
        os.close(current_fd)


def read_bytes_confined(
    root: Path,
    relative_path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Read a stable regular file through a parent descriptor pinned below ``root``."""

    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")

    with _open_confined_parent(
        root,
        relative_path,
        create_parents=False,
        label=label,
    ) as (parent_fd, name):
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | os.O_NOFOLLOW
        try:
            file_fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise ValueError(f"{label} is a symlink and has ambiguous ownership") from exc
            raise
        try:
            opened = os.fstat(file_fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(current.st_mode)
                or _identity(opened) != _identity(current)
            ):
                raise ValueError(f"{label} changed identity during confined read")
            initial_signature = _stable_file_signature(opened)

            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:
                chunk = os.read(file_fd, min(_READ_CHUNK_BYTES, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"{label} exceeds {max_bytes} byte ingestion limit")

            final_opened = os.fstat(file_fd)
            final_current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _stable_file_signature(final_opened) != initial_signature
                or not stat.S_ISREG(final_current.st_mode)
                or _identity(final_opened) != _identity(final_current)
            ):
                raise ValueError(f"{label} changed during confined read")
            return b"".join(chunks)
        finally:
            os.close(file_fd)


def atomic_write_bytes_confined(
    root: Path,
    relative_path: str | Path,
    data: bytes,
    *,
    create_parents: bool,
    create_only: bool,
    label: str,
) -> None:
    """Atomically publish bytes below a descriptor-pinned root.

    The final rename/link is descriptor-relative, so replacing a pathname parent
    with a symlink after validation cannot redirect publication into another tree.
    """

    with _open_confined_parent(
        root,
        relative_path,
        create_parents=create_parents,
        label=label,
    ) as (parent_fd, name):
        temp_name = f".{name}.{uuid4().hex}.aiqa.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | os.O_NOFOLLOW
        )
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        temp_exists = True
        try:
            with os.fdopen(temp_fd, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temp_fd = -1

            if create_only:
                os.link(
                    temp_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                os.unlink(temp_name, dir_fd=parent_fd)
                temp_exists = False
            else:
                try:
                    existing = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    existing = None
                if existing is not None and stat.S_ISLNK(existing.st_mode):
                    raise ValueError(f"{label} target is a symlink and has ambiguous ownership")
                os.rename(
                    temp_name,
                    name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                temp_exists = False
            os.fsync(parent_fd)
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            if temp_exists:
                with suppress(FileNotFoundError):
                    os.unlink(temp_name, dir_fd=parent_fd)


def unlink_file_confined(
    root: Path,
    relative_path: str | Path,
    *,
    missing_ok: bool,
    label: str,
) -> bool:
    """Remove one regular file from the descriptor-pinned tree and fsync its parent."""

    with _open_confined_parent(
        root,
        relative_path,
        create_parents=False,
        label=label,
    ) as (parent_fd, name):
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if missing_ok:
                return False
            raise
        if stat.S_ISLNK(current.st_mode):
            raise ValueError(f"{label} target is a symlink and has ambiguous ownership")
        if not stat.S_ISREG(current.st_mode):
            raise ValueError(f"{label} target must be a regular file")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True
