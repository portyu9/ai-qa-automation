from __future__ import annotations

import hashlib
import io
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .mermaid_fs import (
        MAX_MARKDOWN_BYTES,
        MAX_MARKDOWN_FILES,
        MAX_MERMAID_DIAGRAMS,
        MAX_TOTAL_MARKDOWN_BYTES,
        PUBLIC_ROOT_MARKDOWN,
        READ_CHUNK_BYTES,
        _dirflag,
        _nofollow,
        _read_regular_bytes,
        _read_regular_bytes_at,
        _sig,
    )
else:
    from mermaid_fs import (
        MAX_MARKDOWN_BYTES,
        MAX_MARKDOWN_FILES,
        MAX_MERMAID_DIAGRAMS,
        MAX_TOTAL_MARKDOWN_BYTES,
        PUBLIC_ROOT_MARKDOWN,
        READ_CHUNK_BYTES,
        _dirflag,
        _nofollow,
        _read_regular_bytes,
        _read_regular_bytes_at,
        _sig,
    )

FENCE_OPEN_RE = re.compile(r"^(?P<fence>`{3,}|~{3,})[ \t]*(?P<info>[A-Za-z0-9_+.-]*)[ \t]*$")


@dataclass(frozen=True)
class MermaidDocumentSnapshot:
    relative_path: Path
    diagram_count: int
    content: bytes
    sha256: str


def _parse_fence_open(line: str) -> tuple[str, int, str] | None:
    match = FENCE_OPEN_RE.match(line.strip())
    if match is None:
        return None
    fence = match.group("fence")
    return fence[0], len(fence), match.group("info").lower()


def _is_fence_close(line: str, *, fence_char: str, minimum_length: int) -> bool:
    stripped = line.strip()
    return (
        len(stripped) >= minimum_length
        and bool(stripped)
        and all(character == fence_char for character in stripped)
    )


def _mermaid_block_count(text: str) -> int:
    count = 0
    fence: tuple[str, int, str] | None = None
    for line in io.StringIO(text):
        if fence is None:
            fence = _parse_fence_open(line)
            if fence is not None and fence[2] == "mermaid":
                count += 1
            continue
        if _is_fence_close(line, fence_char=fence[0], minimum_length=fence[1]):
            fence = None
    if fence is not None:
        raise ValueError("unterminated fenced code block in public documentation")
    return count


def discover_mermaid_snapshot(
    root: Path,
    *,
    snapshot_factory: Callable[[Path, bytes], MermaidDocumentSnapshot | None],
) -> list[MermaidDocumentSnapshot]:
    before = root.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("repository root must be a real directory")
    root_fd = os.open(root, os.O_RDONLY | _dirflag() | _nofollow())
    docs_fd: int | None = None
    selected: list[MermaidDocumentSnapshot] = []
    total_bytes = 0
    diagrams = 0
    try:
        opened = os.fstat(root_fd)
        if not stat.S_ISDIR(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise ValueError("repository root changed before bounded ingestion")
        for name in PUBLIC_ROOT_MARKDOWN:
            data = _read_regular_bytes_at(
                root_fd, name, max_bytes=MAX_MARKDOWN_BYTES, label="documentation file"
            )
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_MARKDOWN_BYTES:
                raise ValueError(
                    f"documentation corpus exceeds {MAX_TOTAL_MARKDOWN_BYTES} total Markdown bytes"
                )
            snapshot = snapshot_factory(Path(name), data)
            if snapshot:
                diagrams += snapshot.diagram_count
                if diagrams > MAX_MERMAID_DIAGRAMS:
                    raise ValueError(
                        f"documentation corpus exceeds {MAX_MERMAID_DIAGRAMS} Mermaid diagrams"
                    )
                selected.append(snapshot)
        docs_before = os.stat("docs", dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(docs_before.st_mode) or not stat.S_ISDIR(docs_before.st_mode):
            raise ValueError("docs must be a real directory, not a symlink")
        docs_fd = os.open("docs", os.O_RDONLY | _dirflag() | _nofollow(), dir_fd=root_fd)
        docs_opened = os.fstat(docs_fd)
        if (docs_opened.st_dev, docs_opened.st_ino) != (docs_before.st_dev, docs_before.st_ino):
            raise ValueError("docs changed before bounded enumeration")
        names: list[str] = []
        with os.scandir(docs_fd) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_MARKDOWN_FILES:
                    raise ValueError(f"docs exceeds {MAX_MARKDOWN_FILES} direct entries")
                if Path(entry.name).suffix.lower() == ".md":
                    names.append(entry.name)
        if len(PUBLIC_ROOT_MARKDOWN) + len(names) > MAX_MARKDOWN_FILES:
            raise ValueError(f"documentation corpus exceeds {MAX_MARKDOWN_FILES} Markdown files")
        for name in sorted(names):
            data = _read_regular_bytes_at(
                docs_fd, name, max_bytes=MAX_MARKDOWN_BYTES, label="documentation file"
            )
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_MARKDOWN_BYTES:
                raise ValueError(
                    f"documentation corpus exceeds {MAX_TOTAL_MARKDOWN_BYTES} total Markdown bytes"
                )
            snapshot = snapshot_factory(Path("docs") / name, data)
            if snapshot:
                diagrams += snapshot.diagram_count
                if diagrams > MAX_MERMAID_DIAGRAMS:
                    raise ValueError(
                        f"documentation corpus exceeds {MAX_MERMAID_DIAGRAMS} Mermaid diagrams"
                    )
                selected.append(snapshot)
        if _sig(docs_opened) != _sig(os.fstat(docs_fd)) or _sig(opened) != _sig(os.fstat(root_fd)):
            raise ValueError("documentation corpus changed during bounded ingestion")
    finally:
        if docs_fd is not None:
            os.close(docs_fd)
        os.close(root_fd)
    current = root.lstat()
    if not stat.S_ISDIR(current.st_mode) or _sig(opened) != _sig(current):
        raise ValueError("repository root path identity changed during bounded ingestion")
    if diagrams > MAX_MERMAID_DIAGRAMS:
        raise ValueError(f"documentation corpus exceeds {MAX_MERMAID_DIAGRAMS} Mermaid diagrams")
    if not selected:
        raise ValueError("no Mermaid diagrams discovered in the public Markdown corpus")
    return selected


def _write_snapshot(root: Path, item: MermaidDocumentSnapshot) -> None:
    path = root / item.relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(item.content)
        while view:
            written = os.write(fd, view[:READ_CHUNK_BYTES])
            if written <= 0:
                raise RuntimeError(f"could not complete Mermaid source snapshot for {item.relative_path}")
            view = view[written:]
    finally:
        os.close(fd)
    observed = _read_regular_bytes(path, max_bytes=MAX_MARKDOWN_BYTES, label="Mermaid source snapshot")
    if hashlib.sha256(observed).hexdigest() != item.sha256:
        raise RuntimeError(f"Mermaid source snapshot identity mismatch for {item.relative_path}")
