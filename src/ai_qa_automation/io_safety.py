from __future__ import annotations

import hashlib
from pathlib import Path

_READ_CHUNK_BYTES = 1024 * 1024


def _validated_bound(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    return max_bytes


def read_bytes_bounded(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Read at most ``max_bytes`` and fail if the subject grows beyond the bound.

    Callers may preflight ``stat()`` for fast rejection, but this read is the
    authoritative ingestion boundary. Reading ``max_bytes + 1`` prevents a file
    that changes after preflight from turning a bounded restore/validation path
    into an unbounded-memory operation.
    """

    limit = _validated_bound(max_bytes)
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
    return content


def read_text_bounded(path: Path, *, max_bytes: int, label: str) -> str:
    """Read bounded UTF-8 text without a stat/read TOCTOU size gap."""

    return read_bytes_bounded(path, max_bytes=max_bytes, label=label).decode("utf-8")


def sha256_file_bounded(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    """Hash one file while enforcing the byte bound during the actual read."""

    limit = _validated_bound(max_bytes)
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
            digest.update(chunk)
    return digest.hexdigest(), total
