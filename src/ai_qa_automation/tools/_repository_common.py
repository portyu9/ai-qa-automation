from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^:+-]{0,255}$")
_HEX_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_GIT_MODE = re.compile(r"^[0-7]{6}$")
_GIT_GRAFT_WARNING = "info/grafts"
_MAX_FINGERPRINT_CHANGED_FILES = 1000
_MAX_FINGERPRINT_FILE_BYTES = 16_000_000
_MAX_FINGERPRINT_TOTAL_BYTES = 128_000_000
_MAX_GIT_TEXT_OUTPUT_BYTES = 8_000_000
_MAX_GIT_EXACT_STDOUT_BYTES = 16_000_000
_MAX_GIT_EXACT_STDERR_BYTES = 256_000
_MAX_GIT_INDEX_BYTES = 16_000_000
_MAX_GIT_PATHS = 100_000
_MAX_GIT_METADATA_SCAN_ENTRIES = 100_000
_MAX_GIT_CONFIG_BYTES = 256_000


def raise_if_git_grafts_reported(stderr: str) -> None:
    if _GIT_GRAFT_WARNING in stderr.casefold():
        raise RuntimeError("Git graft metadata is not permitted during repository inspection")


def _git_index_oid_bytes(raw: bytes) -> int:
    matches: list[int] = []
    for oid_bytes in (20, 32):
        if len(raw) <= oid_bytes:
            continue
        body = raw[:-oid_bytes]
        expected = raw[-oid_bytes:]
        if oid_bytes == 20:
            observed = hashlib.sha1(body, usedforsecurity=False).digest()
        else:
            observed = hashlib.sha256(body).digest()
        if observed == expected:
            matches.append(oid_bytes)
    if len(matches) != 1:
        raise RuntimeError("Git index checksum is invalid or ambiguous")
    return matches[0]


def _decode_index_v4_strip_count(raw: bytes, offset: int, limit: int) -> tuple[int, int]:
    if offset >= limit:
        raise RuntimeError("Git index v4 entry is truncated")
    value = raw[offset] & 0x7F
    byte = raw[offset]
    offset += 1
    consumed = 1
    while byte & 0x80:
        if offset >= limit or consumed >= 10:
            raise RuntimeError("Git index v4 path compression is malformed")
        byte = raw[offset]
        offset += 1
        consumed += 1
        value = ((value + 1) << 7) + (byte & 0x7F)
    return value, offset


def git_index_has_split_link(raw: bytes) -> bool:
    """Return whether a bounded Git index contains the mandatory split-index link extension.

    The parser validates the index header, checksum, entry framing, and extension framing
    before trusting extension signatures. It supports Git index versions 2 through 4 and
    both SHA-1 and SHA-256 repositories. Malformed index bytes fail closed.
    """

    if not raw:
        return False
    if len(raw) < 32 or raw[:4] != b"DIRC":
        raise RuntimeError("Git index header is malformed")

    version = int.from_bytes(raw[4:8], "big")
    entry_count = int.from_bytes(raw[8:12], "big")
    if version not in {2, 3, 4}:
        raise RuntimeError("Git index version is unsupported")
    if entry_count > _MAX_GIT_PATHS:
        raise RuntimeError("Git index entry count exceeds the bounded path budget")

    oid_bytes = _git_index_oid_bytes(raw)
    content_end = len(raw) - oid_bytes
    offset = 12
    previous_path = b""

    for _ in range(entry_count):
        entry_start = offset
        fixed_bytes = 40 + oid_bytes + 2
        if offset + fixed_bytes > content_end:
            raise RuntimeError("Git index entry is truncated")
        flags_offset = offset + 40 + oid_bytes
        flags = int.from_bytes(raw[flags_offset : flags_offset + 2], "big")
        offset += fixed_bytes

        if flags & 0x4000:
            if version < 3 or offset + 2 > content_end:
                raise RuntimeError("Git index extended flags are malformed")
            offset += 2

        if version in {2, 3}:
            nul = raw.find(b"\0", offset, content_end)
            if nul < 0:
                raise RuntimeError("Git index pathname is not NUL terminated")
            path = raw[offset:nul]
            stored_length = flags & 0x0FFF
            if stored_length < 0x0FFF and stored_length != len(path):
                raise RuntimeError("Git index pathname length is inconsistent")
            if stored_length == 0x0FFF and len(path) < 0x0FFF:
                raise RuntimeError("Git index long-path marker is inconsistent")
            consumed = nul + 1 - entry_start
            next_offset = entry_start + ((consumed + 7) // 8) * 8
            if next_offset > content_end or any(raw[nul + 1 : next_offset]):
                raise RuntimeError("Git index entry padding is malformed")
            offset = next_offset
            previous_path = path
            continue

        strip_count, offset = _decode_index_v4_strip_count(raw, offset, content_end)
        if strip_count > len(previous_path):
            raise RuntimeError("Git index v4 path compression exceeds the previous path")
        nul = raw.find(b"\0", offset, content_end)
        if nul < 0:
            raise RuntimeError("Git index v4 pathname is not NUL terminated")
        path = previous_path[: len(previous_path) - strip_count] + raw[offset:nul]
        stored_length = flags & 0x0FFF
        if stored_length < 0x0FFF and stored_length != len(path):
            raise RuntimeError("Git index v4 pathname length is inconsistent")
        if stored_length == 0x0FFF and len(path) < 0x0FFF:
            raise RuntimeError("Git index v4 long-path marker is inconsistent")
        previous_path = path
        offset = nul + 1

    while offset < content_end:
        if offset + 8 > content_end:
            raise RuntimeError("Git index extension header is truncated")
        signature = raw[offset : offset + 4]
        size = int.from_bytes(raw[offset + 4 : offset + 8], "big")
        next_offset = offset + 8 + size
        if next_offset > content_end:
            raise RuntimeError("Git index extension exceeds the bounded index bytes")
        if signature == b"link":
            return True
        offset = next_offset

    if offset != content_end:
        raise RuntimeError("Git index extension framing is malformed")
    return False


class RepositorySubjectError(RuntimeError):
    """Raised when Git inspection cannot remain bound to the authorized workspace subject."""


@dataclass(frozen=True)
class RepositorySnapshot:
    workspace: str
    git_sha: str | None
    branch: str | None
    status: str
    changed_files: tuple[str, ...]
    fingerprint: str
    fingerprint_complete: bool
    fingerprint_incomplete_reasons: tuple[str, ...]


@dataclass(frozen=True)
class RepositoryChangeSet:
    """Diff-aware change set anchored to an explicit trusted baseline ref."""

    requested_base_ref: str
    baseline_sha: str
    merge_base_sha: str
    head_sha: str
    committed_files: tuple[str, ...]
    worktree_files: tuple[str, ...]
    changed_files: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "requested_base_ref": self.requested_base_ref,
            "baseline_sha": self.baseline_sha,
            "merge_base_sha": self.merge_base_sha,
            "head_sha": self.head_sha,
            "committed_files": list(self.committed_files),
            "worktree_files": list(self.worktree_files),
            "changed_files": list(self.changed_files),
        }
