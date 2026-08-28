from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MERMAID_IMAGE = (
    "ghcr.io/mermaid-js/mermaid-cli/mermaid-cli@"
    "sha256:8cc6fb93037759668ac6c48d3b727da15c60419304f3bd4c69c8cd8589e2b485"
)
PUBLIC_ROOT_MARKDOWN = ("README.md", "CONTRIBUTING.md", "SECURITY.md")
FENCE_OPEN_RE = re.compile(r"^(?P<fence>`{3,}|~{3,})[ \t]*(?P<info>[A-Za-z0-9_+.-]*)[ \t]*$")
GITHUB_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_MARKDOWN_FILES = 128
MAX_MARKDOWN_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MARKDOWN_BYTES = 16 * 1024 * 1024
MAX_MERMAID_DIAGRAMS = 256
MAX_RENDER_FILE_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
RENDER_TIMEOUT_SECONDS = 60


def _stable_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _require_nofollow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", None)
    if flag is None:
        raise RuntimeError("Mermaid validation requires O_NOFOLLOW filesystem support")
    return flag


def _read_fd_bounded(fd: int, *, max_bytes: int, label: str) -> bytes:
    data = bytearray()
    while True:
        remaining = max_bytes + 1 - len(data)
        if remaining <= 0:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
        chunk = os.read(fd, min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes")
    return bytes(data)


def _read_regular_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file: {path}")
    if before.st_size > max_bytes:
        raise ValueError(f"{label} exceeds {max_bytes} bytes: {path}")

    try:
        fd = os.open(path, os.O_RDONLY | _require_nofollow_flag())
    except OSError as exc:
        raise ValueError(f"{label} could not be opened without following links: {path}") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"{label} must remain a regular file while open: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError(f"{label} changed before bounded ingestion: {path}")
        if opened.st_size > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes: {path}")
        data = _read_fd_bounded(fd, max_bytes=max_bytes, label=label)
        after = os.fstat(fd)
    finally:
        os.close(fd)

    try:
        current = path.lstat()
    except FileNotFoundError as exc:
        raise ValueError(f"{label} disappeared during bounded ingestion: {path}") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
        raise ValueError(f"{label} changed type during bounded ingestion: {path}")
    if _stable_signature(opened) != _stable_signature(after):
        raise ValueError(f"{label} changed while being read: {path}")
    if _stable_signature(after) != _stable_signature(current):
        raise ValueError(f"{label} path identity changed during bounded ingestion: {path}")
    return data


def _ci_identity() -> tuple[str | None, str | None]:
    subject_sha = os.environ.get("CI_SUBJECT_SHA")
    github_event_sha = os.environ.get("GITHUB_SHA")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for name, value in (
            ("CI_SUBJECT_SHA", subject_sha),
            ("GITHUB_SHA", github_event_sha),
        ):
            if value is None or GITHUB_SHA_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a full lowercase GitHub commit SHA in CI")
    return subject_sha, github_event_sha


def _candidate_files(root: Path) -> list[Path]:
    candidates = [root / name for name in PUBLIC_ROOT_MARKDOWN]
    docs = root / "docs"
    try:
        before = docs.lstat()
    except FileNotFoundError as exc:
        raise ValueError("docs directory is required for Mermaid validation") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ValueError("docs must be a real directory, not a symlink")

    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(docs, os.O_RDONLY | directory_flag | _require_nofollow_flag())
    except OSError as exc:
        raise ValueError("docs could not be opened without following links") from exc
    names: list[str] = []
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ValueError("docs must remain a directory while open")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
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

    try:
        current = docs.lstat()
    except FileNotFoundError as exc:
        raise ValueError("docs disappeared during bounded enumeration") from exc
    if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
        raise ValueError("docs changed type during bounded enumeration")
    if _stable_signature(opened) != _stable_signature(after):
        raise ValueError("docs changed during bounded enumeration")
    if _stable_signature(after) != _stable_signature(current):
        raise ValueError("docs path identity changed during bounded enumeration")

    candidates.extend(root / "docs" / name for name in sorted(names))
    return candidates


def _read_regular_file(path: Path) -> str:
    data = _read_regular_bytes(
        path,
        max_bytes=MAX_MARKDOWN_BYTES,
        label="documentation file",
    )
    return data.decode("utf-8")


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
    fence_char: str | None = None
    minimum_length = 0
    language = ""

    for line in text.splitlines():
        if fence_char is None:
            opened = _parse_fence_open(line)
            if opened is None:
                continue
            fence_char, minimum_length, language = opened
            if language == "mermaid":
                count += 1
            continue

        if _is_fence_close(line, fence_char=fence_char, minimum_length=minimum_length):
            fence_char = None
            minimum_length = 0
            language = ""

    if fence_char is not None:
        raise ValueError("unterminated fenced code block in public documentation")
    return count


def _discover_mermaid_documents(root: Path) -> list[tuple[Path, int]]:
    selected: list[tuple[Path, int]] = []
    total_bytes = 0
    total_diagrams = 0
    candidates = _candidate_files(root)
    if len(candidates) > MAX_MARKDOWN_FILES:
        raise ValueError(f"documentation corpus exceeds {MAX_MARKDOWN_FILES} Markdown files")

    for path in candidates:
        text = _read_regular_file(path)
        total_bytes += len(text.encode("utf-8"))
        if total_bytes > MAX_TOTAL_MARKDOWN_BYTES:
            raise ValueError(
                f"documentation corpus exceeds {MAX_TOTAL_MARKDOWN_BYTES} total Markdown bytes"
            )
        count = _mermaid_block_count(text)
        total_diagrams += count
        if total_diagrams > MAX_MERMAID_DIAGRAMS:
            raise ValueError(
                f"documentation corpus exceeds {MAX_MERMAID_DIAGRAMS} Mermaid diagrams"
            )
        if count:
            selected.append((path.relative_to(root), count))
    if not selected:
        raise ValueError("no Mermaid diagrams discovered in the public Markdown corpus")
    return selected


def _read_transformed_markdown(destination: Path) -> str:
    data = _read_regular_bytes(
        destination,
        max_bytes=MAX_RENDER_FILE_BYTES,
        label="Mermaid transformed Markdown",
    )
    return data.decode("utf-8")


def _validate_generated_svgs(destination: Path, *, expected_count: int) -> None:
    generated_count = 0
    for generated in destination.parent.glob(f"{destination.stem}-*.svg"):
        generated_count += 1
        if generated_count > expected_count:
            raise RuntimeError(
                f"Mermaid CLI rendered more than {expected_count} SVGs for {destination.name}"
            )
        info = generated.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"Mermaid CLI emitted a non-regular SVG: {generated.name}")
        if info.st_size > MAX_RENDER_FILE_BYTES:
            raise RuntimeError(
                f"Mermaid CLI SVG exceeded {MAX_RENDER_FILE_BYTES} bytes: {generated.name}"
            )
    if generated_count != expected_count:
        raise RuntimeError(
            f"Mermaid CLI rendered {generated_count} SVGs for {destination.name}; "
            f"expected {expected_count}"
        )


def _run_mermaid(root: Path, relative_path: Path, output_root: Path, expected_count: int) -> None:
    destination = output_root / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--ulimit",
        f"fsize={MAX_RENDER_FILE_BYTES}:{MAX_RENDER_FILE_BYTES}",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--env",
        "HOME=/tmp",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--mount",
        f"type=bind,src={root},dst=/repo,readonly",
        "--mount",
        f"type=bind,src={output_root},dst=/out",
        MERMAID_IMAGE,
        "-i",
        f"/repo/{relative_path.as_posix()}",
        "-o",
        f"/out/{relative_path.as_posix()}",
    ]
    try:
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=RENDER_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Mermaid render failed for {relative_path}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Mermaid render exceeded {RENDER_TIMEOUT_SECONDS}s for {relative_path}"
        ) from exc

    try:
        transformed = _read_transformed_markdown(destination)
    except ValueError as exc:
        raise RuntimeError(f"invalid Mermaid transformed Markdown for {relative_path}") from exc
    remaining = _mermaid_block_count(transformed)
    if remaining:
        raise RuntimeError(
            f"Mermaid CLI left {remaining} unrendered Mermaid block(s) in {relative_path}"
        )
    _validate_generated_svgs(destination, expected_count=expected_count)


def main() -> int:
    subject_sha, github_event_sha = _ci_identity()
    root = Path.cwd().resolve()
    documents = _discover_mermaid_documents(root)
    with tempfile.TemporaryDirectory(prefix="aiqa-mermaid-") as temp_dir:
        output_root = Path(temp_dir).resolve()
        for relative_path, count in documents:
            _run_mermaid(root, relative_path, output_root, count)

    result = {
        "schema_version": 2,
        "validator": "official_mermaid_cli_container",
        "container": MERMAID_IMAGE,
        "subject_sha": subject_sha,
        "github_event_sha": github_event_sha,
        "documents": [
            {"path": path.as_posix(), "diagram_count": count} for path, count in documents
        ],
        "document_count": len(documents),
        "diagram_count": sum(count for _, count in documents),
        "failures": 0,
    }
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
