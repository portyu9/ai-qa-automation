from __future__ import annotations

import os
import stat
from pathlib import Path

if __package__:
    from .mermaid_fs import (
        MAX_RENDER_FILE_BYTES,
        MAX_RENDER_OUTPUT_ENTRIES,
        MAX_RENDER_TOTAL_BYTES,
        _dirflag,
        _nofollow,
        _read_regular_bytes_at,
    )
    from .mermaid_snapshot import _mermaid_block_count
else:
    from mermaid_fs import (
        MAX_RENDER_FILE_BYTES,
        MAX_RENDER_OUTPUT_ENTRIES,
        MAX_RENDER_TOTAL_BYTES,
        _dirflag,
        _nofollow,
        _read_regular_bytes_at,
    )
    from mermaid_snapshot import _mermaid_block_count


def _require_empty_render_root(root: Path) -> None:
    fd = os.open(root, os.O_RDONLY | _dirflag() | _nofollow())
    try:
        with os.scandir(fd) as entries:
            if next(entries, None) is not None:
                raise RuntimeError("Mermaid output root must be empty before rendering")
    finally:
        os.close(fd)


def _bounded_output_shape(root_fd: int, *, relative: Path) -> str:
    entries = 0
    regular = 0
    directories = 0
    symlinks = 0
    other = 0
    expected_markdown = False
    expected_svgs = 0
    prefix = f"{relative.stem}-"
    with os.scandir(root_fd) as output_entries:
        for entry in output_entries:
            entries += 1
            if entries > MAX_RENDER_OUTPUT_ENTRIES:
                return f"entries>{MAX_RENDER_OUTPUT_ENTRIES}"
            if entry.name == relative.name:
                expected_markdown = True
            if entry.name.startswith(prefix) and entry.name.endswith(".svg"):
                expected_svgs += 1
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                symlinks += 1
            elif stat.S_ISREG(info.st_mode):
                regular += 1
            elif stat.S_ISDIR(info.st_mode):
                directories += 1
            else:
                other += 1
    return (
        f"entries={entries},regular={regular},directories={directories},"
        f"symlinks={symlinks},other={other},expected_markdown={expected_markdown},"
        f"expected_svgs={expected_svgs}"
    )


def _validate_rendered_outputs(root: Path, relative: Path, *, expected_count: int) -> None:
    if relative.is_absolute() or relative.parent != Path("."):
        raise RuntimeError("Mermaid renderer output must use the flat private output namespace")
    root_fd = os.open(root, os.O_RDONLY | _dirflag() | _nofollow())
    try:
        try:
            rendered_bytes = _read_regular_bytes_at(
                root_fd,
                relative.name,
                max_bytes=MAX_RENDER_FILE_BYTES,
                label="Mermaid transformed Markdown",
            )
            rendered = rendered_bytes.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            shape = _bounded_output_shape(root_fd, relative=relative)
            raise RuntimeError(f"invalid Mermaid transformed Markdown; output shape: {shape}") from exc
        remaining = _mermaid_block_count(rendered)
        if remaining:
            raise RuntimeError(
                f"Mermaid CLI left {remaining} unrendered Mermaid block(s) in transformed Markdown"
            )

        prefix = f"{relative.stem}-"
        count = 0
        total_bytes = len(rendered_bytes)
        with os.scandir(root_fd) as entries:
            for index, entry in enumerate(entries, start=1):
                if index > MAX_RENDER_OUTPUT_ENTRIES:
                    raise RuntimeError("Mermaid CLI exceeded the bounded output-entry budget")
                if entry.name == relative.name:
                    continue
                if not entry.name.startswith(prefix) or not entry.name.endswith(".svg"):
                    raise RuntimeError(
                        f"Mermaid CLI emitted an unexpected output entry: {entry.name}"
                    )
                count += 1
                if count > expected_count:
                    raise RuntimeError(
                        f"Mermaid CLI rendered more than {expected_count} SVGs for {relative.name}"
                    )
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise RuntimeError(f"Mermaid CLI emitted a non-regular SVG: {entry.name}")
                if info.st_size == 0:
                    raise RuntimeError(f"Mermaid CLI emitted an empty SVG: {entry.name}")
                if info.st_size > MAX_RENDER_FILE_BYTES:
                    raise RuntimeError(
                        f"Mermaid CLI SVG exceeded {MAX_RENDER_FILE_BYTES} bytes: {entry.name}"
                    )
                total_bytes += info.st_size
                if total_bytes > MAX_RENDER_TOTAL_BYTES:
                    raise RuntimeError(
                        f"Mermaid CLI outputs exceeded {MAX_RENDER_TOTAL_BYTES} aggregate bytes"
                    )
        if count != expected_count:
            raise RuntimeError(
                f"Mermaid CLI rendered {count} SVGs for {relative.name}; expected {expected_count}"
            )
    finally:
        os.close(root_fd)


def _validate_generated_svgs(destination: Path, *, expected_count: int) -> None:
    parent_fd = os.open(destination.parent, os.O_RDONLY | _dirflag() | _nofollow())
    try:
        prefix = f"{destination.stem}-"
        count = 0
        with os.scandir(parent_fd) as entries:
            for entry in entries:
                if not entry.name.startswith(prefix) or not entry.name.endswith(".svg"):
                    continue
                count += 1
                if count > expected_count:
                    raise RuntimeError(
                        f"Mermaid CLI rendered more than {expected_count} SVGs for {destination.name}"
                    )
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise RuntimeError(f"Mermaid CLI emitted a non-regular SVG: {entry.name}")
                if info.st_size == 0:
                    raise RuntimeError(f"Mermaid CLI emitted an empty SVG: {entry.name}")
                if info.st_size > MAX_RENDER_FILE_BYTES:
                    raise RuntimeError(
                        f"Mermaid CLI SVG exceeded {MAX_RENDER_FILE_BYTES} bytes: {entry.name}"
                    )
        if count != expected_count:
            raise RuntimeError(
                f"Mermaid CLI rendered {count} SVGs for {destination.name}; expected {expected_count}"
            )
    finally:
        os.close(parent_fd)
