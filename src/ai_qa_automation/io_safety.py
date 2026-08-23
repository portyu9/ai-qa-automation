from __future__ import annotations

import errno
import hashlib
import os
import stat
from pathlib import Path
from typing import BinaryIO

_READ_CHUNK_BYTES = 1024 * 1024


def _validated_bound(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    return max_bytes


def _open_regular_binary(path: Path, *, label: str) -> BinaryIO:
    """Open a regular file without following a final-component symlink when supported."""

    if path.is_symlink():
        raise ValueError(f"{label} is a symlink and has ambiguous ownership")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if nofollow and exc.errno == errno.ELOOP:
            raise ValueError(f"{label} became a symlink during bounded ingestion") from exc
        raise
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{label} must be a regular file")
        if not nofollow:
            # Platforms without O_NOFOLLOW still get a post-open ownership check.
            # Once this check passes, reads use the already-open descriptor rather
            # than resolving the path again.
            current = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode):
                raise ValueError(f"{label} is a symlink and has ambiguous ownership")
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError(f"{label} changed identity during bounded ingestion")
        return os.fdopen(fd, "rb")
    except Exception:
        os.close(fd)
        raise


def read_bytes_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read at most ``max_bytes`` and fail if the subject grows beyond the bound.

    Callers may preflight ``stat()`` for fast rejection, but this read is the
    authoritative ingestion boundary. Reading ``max_bytes + 1`` prevents a file
    that changes after preflight from turning a bounded restore/validation path
    into an unbounded-memory operation.
    """

    limit = _validated_bound(max_bytes)
    with _open_regular_binary(path, label=label) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
    return content


def read_text_bounded(path: Path, *, max_bytes: int, label: str) -> str:
    """Read bounded UTF-8 text without a stat/read TOCTOU size gap."""

    return read_bytes_bounded(path, max_bytes=max_bytes, label=label).decode("utf-8")


def sha256_file_bounded(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    """Hash one regular file while enforcing the byte bound during the actual read."""

    limit = _validated_bound(max_bytes)
    digest = hashlib.sha256()
    total = 0
    with _open_regular_binary(path, label=label) as stream:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
            digest.update(chunk)
    return digest.hexdigest(), total
