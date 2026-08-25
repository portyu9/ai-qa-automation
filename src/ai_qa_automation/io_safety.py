from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterator
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO
from uuid import UUID

_READ_CHUNK_BYTES = 1024 * 1024


def _validated_bound(max_bytes: int) -> int:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    return max_bytes


def _validated_entry_bound(max_entries: int) -> int:
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
        raise ValueError("max_entries must be a positive integer")
    return max_entries


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


def _stable_directory_signature(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


class JsonSerializationBoundsError(ValueError):
    """JSON serialization exceeded a deterministic shape or byte ceiling."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_JSON_SERIALIZATION_MAX_DEPTH = 128
_JSON_SERIALIZATION_MAX_NODES = 1_000_000
_JSON_SERIALIZATION_MAX_CONTAINER_ITEMS = 100_000
_JSON_SERIALIZATION_MAX_INTEGER_BITS = 4096


def _json_string_size_bounded(
    value: str,
    *,
    remaining: int,
    ensure_ascii: bool,
    label: str,
) -> int:
    """Count one encoded JSON string without constructing its escaped copy."""

    if remaining < 2:
        raise JsonSerializationBoundsError(
            "bytes", f"{label} exceeds the deterministic JSON byte limit"
        )
    total = 2  # opening and closing quotes
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise JsonSerializationBoundsError("unicode", f"{label} contains invalid Unicode")
        if character in {'"', "\\"} or character in {"\b", "\f", "\n", "\r", "\t"}:
            width = 2
        elif codepoint <= 0x1F:
            width = 6
        elif ensure_ascii and codepoint > 0x7F:
            width = 6 if codepoint <= 0xFFFF else 12
        elif codepoint <= 0x7F:
            width = 1
        elif codepoint <= 0x7FF:
            width = 2
        elif codepoint <= 0xFFFF:
            width = 3
        else:
            width = 4
        total += width
        if total > remaining:
            raise JsonSerializationBoundsError(
                "bytes", f"{label} exceeds the deterministic JSON byte limit"
            )
    return total


def _preflight_json_serialization(
    value: Any,
    *,
    max_bytes: int,
    label: str,
    ensure_ascii: bool,
    default: Callable[[Any], Any] | None,
) -> None:
    """Bound JSON shape and escaped strings before the standard encoder runs."""

    limit = _validated_bound(max_bytes)
    active: set[int] = set()
    nodes = 0
    escaped_string_bytes = 0

    def visit(item: Any, *, depth: int) -> None:
        nonlocal escaped_string_bytes, nodes
        if depth > _JSON_SERIALIZATION_MAX_DEPTH:
            raise JsonSerializationBoundsError(
                "depth", f"{label} exceeds the deterministic JSON nesting-depth limit"
            )
        nodes += 1
        if nodes > _JSON_SERIALIZATION_MAX_NODES:
            raise JsonSerializationBoundsError(
                "nodes", f"{label} exceeds the deterministic JSON structural-node limit"
            )

        if isinstance(item, str):
            escaped_string_bytes += _json_string_size_bounded(
                item,
                remaining=limit - escaped_string_bytes,
                ensure_ascii=ensure_ascii,
                label=label,
            )
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if item.bit_length() > _JSON_SERIALIZATION_MAX_INTEGER_BITS:
                raise JsonSerializationBoundsError(
                    "integer", f"{label} contains an integer outside the serialization bound"
                )
            return
        if isinstance(item, float):
            if item != item or item in {float("inf"), float("-inf")}:
                raise JsonSerializationBoundsError(
                    "number", f"{label} contains a non-finite JSON number"
                )
            return
        if isinstance(item, dict):
            if len(item) > _JSON_SERIALIZATION_MAX_CONTAINER_ITEMS:
                raise JsonSerializationBoundsError(
                    "container_items", f"{label} contains an oversized JSON object"
                )
            identity = id(item)
            if identity in active:
                raise JsonSerializationBoundsError(
                    "cycle", f"{label} contains a circular JSON value"
                )
            active.add(identity)
            try:
                for key, nested in item.items():
                    if not isinstance(key, str):
                        raise JsonSerializationBoundsError(
                            "dict_key_type", f"{label} contains a non-string JSON object key"
                        )
                    escaped_string_bytes += _json_string_size_bounded(
                        key,
                        remaining=limit - escaped_string_bytes,
                        ensure_ascii=ensure_ascii,
                        label=label,
                    )
                    visit(nested, depth=depth + 1)
            finally:
                active.remove(identity)
            return
        if isinstance(item, (list, tuple)):
            if len(item) > _JSON_SERIALIZATION_MAX_CONTAINER_ITEMS:
                raise JsonSerializationBoundsError(
                    "container_items", f"{label} contains an oversized JSON array"
                )
            identity = id(item)
            if identity in active:
                raise JsonSerializationBoundsError(
                    "cycle", f"{label} contains a circular JSON value"
                )
            active.add(identity)
            try:
                for nested in item:
                    visit(nested, depth=depth + 1)
            finally:
                active.remove(identity)
            return

        if default is None:
            raise TypeError(f"Object of type {type(item).__name__} is not JSON serializable")
        identity = id(item)
        if identity in active:
            raise JsonSerializationBoundsError("cycle", f"{label} contains a circular JSON value")
        active.add(identity)
        try:
            rendered = default(item)
            if rendered is item:
                raise TypeError(f"JSON default returned the original {type(item).__name__} value")
            visit(rendered, depth=depth)
        finally:
            active.remove(identity)

    visit(value, depth=0)


def iter_json_text_bounded(
    value: Any,
    *,
    max_bytes: int,
    label: str,
    indent: int | None = None,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    separators: tuple[str, str] | None = None,
    default: Callable[[Any], Any] | None = None,
    preflight_default: Callable[[Any], Any] | None = None,
) -> Iterator[str]:
    """Preflight JSON shape, then incrementally enforce the exact byte ceiling."""

    limit = _validated_bound(max_bytes)
    _preflight_json_serialization(
        value,
        max_bytes=limit,
        label=label,
        ensure_ascii=ensure_ascii,
        default=preflight_default if preflight_default is not None else default,
    )
    encoder = json.JSONEncoder(
        ensure_ascii=ensure_ascii,
        allow_nan=False,
        indent=indent,
        sort_keys=sort_keys,
        separators=separators,
        default=default,
    )
    total = 0
    try:
        for chunk in encoder.iterencode(value):
            encoded = chunk.encode("utf-8")
            total += len(encoded)
            if total > limit:
                raise JsonSerializationBoundsError(
                    "bytes", f"{label} exceeds the deterministic JSON byte limit"
                )
            yield chunk
    except UnicodeEncodeError as exc:
        raise JsonSerializationBoundsError("unicode", f"{label} contains invalid Unicode") from exc


def json_size_bounded(
    value: Any,
    *,
    max_bytes: int,
    label: str,
    indent: int | None = None,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    separators: tuple[str, str] | None = None,
    default: Callable[[Any], Any] | None = None,
    preflight_default: Callable[[Any], Any] | None = None,
) -> int:
    """Return exact serialized UTF-8 size without retaining the complete JSON text."""

    total = 0
    for chunk in iter_json_text_bounded(
        value,
        max_bytes=max_bytes,
        label=label,
        indent=indent,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
        separators=separators,
        default=default,
        preflight_default=preflight_default,
    ):
        total += len(chunk.encode("utf-8"))
    return total


def json_preflight_scalar_default(value: Any) -> Any:
    """Map deterministic scalar types that Pydantic JSON mode renders as JSON strings/values.

    This helper is intentionally narrow. Mutable/unordered or opaque custom values
    are not admitted through authority-bearing persistence merely because Pydantic
    may be able to coerce or stringify them later.
    """

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        rendered = value.isoformat()
        return rendered[:-6] + "Z" if rendered.endswith("+00:00") else rendered
    if isinstance(value, (date, time, Decimal, UUID, Path)):
        return str(value)
    raise TypeError(f"unsupported deterministic JSON scalar: {type(value).__name__}")


def parse_json_object_strict(text: str, *, label: str) -> dict[str, Any]:
    """Parse one unambiguous standards-compliant JSON object.

    Authority-bearing persisted JSON must never rely on Python's default
    last-key-wins behavior or accept non-standard NaN/Infinity constants.
    Duplicate-key rejection applies recursively because ``object_pairs_hook``
    is invoked for every decoded object.
    """

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label} contains non-standard JSON numeric constant: {value}")

    parsed = json.loads(
        text,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_constant,
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} root must be a JSON object")
    return parsed


def fsync_directory(path: Path) -> None:
    """Durably persist directory-entry changes on platforms that expose directory fsync."""

    if os.name == "nt":  # Python does not expose a portable Windows directory flush primitive.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def open_regular_binary(path: Path, *, label: str) -> BinaryIO:
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
            current = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode):
                raise ValueError(f"{label} is a symlink and has ambiguous ownership")
            if _identity(opened) != _identity(current):
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
    with open_regular_binary(path, label=label) as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
    return content


def read_text_bounded(path: Path, *, max_bytes: int, label: str) -> str:
    """Read bounded UTF-8 text without a stat/read TOCTOU size gap."""

    return read_bytes_bounded(path, max_bytes=max_bytes, label=label).decode("utf-8")


def read_json_object_bounded(path: Path, *, max_bytes: int, label: str) -> dict[str, Any]:
    """Read one bounded JSON object without ambiguous keys or non-standard constants."""

    text = read_text_bounded(path, max_bytes=max_bytes, label=label)
    return parse_json_object_strict(text, label=label)


def _read_fd_bounded(fd: int, *, max_bytes: int, label: str) -> bytes:
    limit = _validated_bound(max_bytes)
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        chunk = os.read(fd, min(_READ_CHUNK_BYTES, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    if total > limit:
        raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
    return b"".join(chunks)


def read_json_catalog_bounded(
    directory: Path,
    *,
    max_entries: int,
    max_bytes_per_file: int,
    label: str,
) -> dict[str, dict[str, Any]]:
    """Read direct ``*.json`` catalog entries through one pinned directory descriptor.

    Authority-bearing catalogs must not be enumerated by pathname after a separate
    symlink preflight. The directory itself is opened no-follow, enumeration is
    bounded while it occurs, each JSON file is opened relative to that descriptor,
    and directory/file identities are revalidated before closure. If the platform
    cannot provide the descriptor-relative primitives required for those guarantees,
    ingestion fails closed rather than silently falling back to racy pathname reads.
    """

    entry_limit = _validated_entry_bound(max_entries)
    file_limit = _validated_bound(max_bytes_per_file)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    supports_secure_relative_io = (
        bool(getattr(os, "O_DIRECTORY", 0))
        and bool(nofollow)
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
    )
    if not supports_secure_relative_io:
        raise RuntimeError(
            f"{label} requires descriptor-relative no-follow directory ingestion on this platform"
        )
    directory_flags |= nofollow

    if directory.is_symlink():
        raise ValueError(f"{label} is a symlink and has ambiguous ownership")
    try:
        directory_fd = os.open(directory, directory_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} became a symlink during catalog ingestion") from exc
        raise

    try:
        opened_directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(opened_directory.st_mode):
            raise ValueError(f"{label} must be a directory")
        try:
            current_directory = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"{label} changed identity during catalog ingestion") from exc
        if stat.S_ISLNK(current_directory.st_mode):
            raise ValueError(f"{label} became a symlink during catalog ingestion")
        if _identity(opened_directory) != _identity(current_directory):
            raise ValueError(f"{label} changed identity during catalog ingestion")
        initial_directory_signature = _stable_directory_signature(opened_directory)

        try:
            entries = os.scandir(directory_fd)
        except (TypeError, NotImplementedError, OSError) as exc:
            raise RuntimeError(
                f"{label} requires descriptor-based directory enumeration on this platform"
            ) from exc

        result: dict[str, dict[str, Any]] = {}
        observed_entries = 0
        with entries:
            for entry in entries:
                observed_entries += 1
                if observed_entries > entry_limit:
                    raise ValueError(f"{label} exceeds {entry_limit} entry ingestion limit")
                name = entry.name
                if not name.endswith(".json"):
                    continue
                if Path(name).name != name or name in {".", ".."}:
                    raise ValueError(f"{label} contains an invalid direct-entry name")

                entry_label = f"{label} entry {name}"
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError(f"{entry_label} must be a regular non-symlink file")

                file_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | nofollow
                try:
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise ValueError(
                            f"{entry_label} became a symlink during catalog ingestion"
                        ) from exc
                    raise
                try:
                    opened_file = os.fstat(file_fd)
                    if not stat.S_ISREG(opened_file.st_mode):
                        raise ValueError(f"{entry_label} must be a regular file")
                    current_file = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(current_file.st_mode):
                        raise ValueError(
                            f"{entry_label} changed file type during catalog ingestion"
                        )
                    if _identity(opened_file) != _identity(current_file):
                        raise ValueError(f"{entry_label} changed identity during catalog ingestion")
                    initial_file_signature = _stable_file_signature(opened_file)

                    content = _read_fd_bounded(
                        file_fd,
                        max_bytes=file_limit,
                        label=entry_label,
                    )

                    final_opened_file = os.fstat(file_fd)
                    final_current_file = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        _stable_file_signature(final_opened_file) != initial_file_signature
                        or _identity(final_opened_file) != _identity(final_current_file)
                        or not stat.S_ISREG(final_current_file.st_mode)
                    ):
                        raise ValueError(f"{entry_label} changed during catalog ingestion")
                finally:
                    os.close(file_fd)

                result[name] = parse_json_object_strict(content.decode("utf-8"), label=entry_label)

        final_opened_directory = os.fstat(directory_fd)
        try:
            final_current_directory = directory.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"{label} changed identity during catalog ingestion") from exc
        if (
            stat.S_ISLNK(final_current_directory.st_mode)
            or not stat.S_ISDIR(final_current_directory.st_mode)
            or _identity(final_opened_directory) != _identity(final_current_directory)
            or _stable_directory_signature(final_opened_directory) != initial_directory_signature
        ):
            raise ValueError(f"{label} changed during catalog ingestion")
        return result
    finally:
        os.close(directory_fd)


def sha256_file_bounded(path: Path, *, max_bytes: int, label: str) -> tuple[str, int]:
    """Hash one regular file while enforcing the byte bound during the actual read."""

    limit = _validated_bound(max_bytes)
    digest = hashlib.sha256()
    total = 0
    with open_regular_binary(path, label=label) as stream:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"{label} exceeds {limit} byte ingestion limit")
            digest.update(chunk)
    return digest.hexdigest(), total
