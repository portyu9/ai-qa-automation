from __future__ import annotations

import os
import stat
from pathlib import Path

PUBLIC_ROOT_MARKDOWN = ("README.md", "CONTRIBUTING.md", "SECURITY.md")
MAX_MARKDOWN_FILES = 128
MAX_MARKDOWN_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MARKDOWN_BYTES = 16 * 1024 * 1024
MAX_MERMAID_DIAGRAMS = 256
MAX_RENDER_FILE_BYTES = 16 * 1024 * 1024
MAX_RENDER_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RENDER_OUTPUT_ENTRIES = 1_024
READ_CHUNK_BYTES = 64 * 1024


def _sig(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _nofollow() -> int:
    value = getattr(os, "O_NOFOLLOW", None)
    if value is None:
        raise RuntimeError("Mermaid validation requires O_NOFOLLOW filesystem support")
    return value


def _dirflag() -> int:
    return getattr(os, "O_DIRECTORY", 0)


def _read_fd_bounded(fd: int, *, max_bytes: int, label: str) -> bytes:
    data = bytearray()
    while True:
        remaining = max_bytes + 1 - len(data)
        if remaining <= 0:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        chunk = os.read(fd, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")


def _read_open_regular(fd: int, before: os.stat_result, *, max_bytes: int, label: str) -> bytes:
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode):
        raise ValueError(f"{label} must remain a regular file while open")
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise ValueError(f"{label} changed before bounded ingestion")
    if opened.st_size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes")
    data = _read_fd_bounded(fd, max_bytes=max_bytes, label=label)
    if _sig(opened) != _sig(os.fstat(fd)):
        raise ValueError(f"{label} changed while being read")
    return data


def _read_regular_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    try:
        fd = os.open(path, os.O_RDONLY | _nofollow())
    except OSError as exc:
        raise ValueError(f"{label} could not be opened without following links: {path}") from exc
    try:
        data = _read_open_regular(fd, before, max_bytes=max_bytes, label=label)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        current = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} disappeared during bounded ingestion: {path}") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or _sig(after) != _sig(current):
        raise ValueError(f"{label} path identity changed during bounded ingestion: {path}")
    return data


def _read_regular_bytes_at(parent_fd: int, name: str, *, max_bytes: int, label: str) -> bytes:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing: {name}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file: {name}")
    try:
        fd = os.open(name, os.O_RDONLY | _nofollow(), dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened without following links: {name}") from exc
    try:
        data = _read_open_regular(fd, before, max_bytes=max_bytes, label=label)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ValueError(f"{label} disappeared during bounded ingestion: {name}") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode) or _sig(after) != _sig(current):
        raise ValueError(f"{label} path identity changed during bounded ingestion: {name}")
    return data


def _candidate_files(root: Path) -> list[Path]:
    candidates = [root / name for name in PUBLIC_ROOT_MARKDOWN]
    docs = root / "docs"
    try:
        before = docs.lstat()
    except FileNotFoundError as exc:
        raise ValueError("docs directory is required for Mermaid validation") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("docs must be a real directory, not a symlink")
    fd = os.open(docs, os.O_RDONLY | _dirflag() | _nofollow())
    names: list[str] = []
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ValueError("docs changed before bounded enumeration")
        with os.scandir(fd) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_MARKDOWN_FILES:
                    raise ValueError(f"docs exceeds {MAX_MARKDOWN_FILES} direct entries")
                if Path(entry.name).suffix.lower() == ".md":
                    names.append(entry.name)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = docs.lstat()
    if not stat.S_ISDIR(current.st_mode) or _sig(opened) != _sig(after) or _sig(after) != _sig(current):
        raise ValueError("docs path identity changed during bounded enumeration")
    candidates.extend(root / "docs" / name for name in sorted(names))
    return candidates


def _read_regular_file(path: Path) -> str:
    return _read_regular_bytes(path, max_bytes=MAX_MARKDOWN_BYTES, label="documentation file").decode(
        "utf-8"
    )
