from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .fs_authority import (
    append_bytes_confined,
    atomic_write_bytes_confined,
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
    stat_confined_entry,
)
from .io_safety import (
    JsonSerializationBoundsError,
    fsync_directory,
    iter_json_text_bounded,
    json_preflight_scalar_default,
    json_size_bounded,
    open_regular_binary,
    parse_json_object_strict,
    read_json_object_bounded,
    sha256_file_bounded,
)
from .models import ArtifactRecord, EvidenceItem, SanitizationStatus
from .redaction import sanitize

_MAX_EVIDENCE_MANIFEST_BYTES = 16_000_000
_MAX_EVIDENCE_AUDIT_LINE_BYTES = 1_000_000
_MAX_EVIDENCE_AUDIT_BYTES = 64_000_000
_MAX_EVIDENCE_COUNT = 10_000
_MAX_ARTIFACT_BYTES = 32_000_000
_MAX_ARTIFACT_COUNT = 5_000
_MAX_TOTAL_ARTIFACT_BYTES = 256_000_000
_MANIFEST_AUDIT_RESERVE_BYTES = 1_024
_CANONICAL_EVIDENCE_HASH_ALGORITHM = "sha256-canonical-json-sorted-keys"


class _RegistryFieldValue:
    __slots__ = ("model", "name")

    def __init__(self, model: BaseModel, name: str) -> None:
        self.model = model
        self.name = name


def _registry_model_proxy(model: BaseModel) -> dict[str, _RegistryFieldValue]:
    return {name: _RegistryFieldValue(model, name) for name in type(model).model_fields}


def _hash_json_bounded(
    value: Any,
    *,
    max_bytes: int,
    label: str,
    sort_keys: bool = False,
    ensure_ascii: bool = True,
    separators: tuple[str, str] | None = None,
    default: Any = None,
    preflight_default: Any = None,
) -> str:
    """Hash one bounded JSON representation without materializing full text or bytes."""

    digest = hashlib.sha256()
    for chunk in iter_json_text_bounded(
        value,
        max_bytes=max_bytes,
        label=label,
        sort_keys=sort_keys,
        ensure_ascii=ensure_ascii,
        separators=separators,
        default=default,
        preflight_default=preflight_default,
    ):
        digest.update(chunk.encode("utf-8"))
    return f"sha256:{digest.hexdigest()}"


def _write_fd_all(fd: int, content: bytes) -> None:
    """Write all bytes to an already-owned descriptor, handling short writes."""

    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "regulated audit append made no forward progress")
        view = view[written:]


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _is_sha256_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        return False
    try:
        int(value[7:], 16)
    except ValueError:
        return False
    return True


def validate_regulated_audit_binding(value: object) -> dict[str, Any]:
    """Validate the exact manifest authority record for a regulated audit subject."""

    required = {"path", "events", "last_event_hash", "content_hash"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("regulated audit manifest binding structure is invalid")
    if value.get("path") != "audit-log.jsonl":
        raise ValueError("regulated audit manifest path is invalid")
    events = value.get("events")
    if type(events) is not int or events < 0 or events > _MAX_EVIDENCE_COUNT + _MAX_ARTIFACT_COUNT:
        raise ValueError("regulated audit manifest event count is invalid")
    last_event_hash = value.get("last_event_hash")
    if events == 0:
        if last_event_hash != "GENESIS":
            raise ValueError("regulated audit manifest empty head is invalid")
    elif not _is_sha256_digest(last_event_hash):
        raise ValueError("regulated audit manifest head hash is invalid")
    content_hash = value.get("content_hash")
    if content_hash is not None and not _is_sha256_digest(content_hash):
        raise ValueError("regulated audit manifest content hash is invalid")
    if events > 0 and content_hash is None:
        raise ValueError("regulated audit manifest content hash is missing")
    return {
        "path": "audit-log.jsonl",
        "events": events,
        "last_event_hash": last_event_hash,
        "content_hash": content_hash,
    }


def _evidence_item_hash_for_audit(item: EvidenceItem, *, canonical: bool) -> str:
    return _hash_json_bounded(
        _registry_model_proxy(item),
        max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
        label="regulated evidence item hash",
        sort_keys=canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        default=EvidenceStore._manifest_json_default,
        preflight_default=EvidenceStore._manifest_json_preflight_default,
    )


def verify_regulated_audit_subject(
    raw: bytes,
    *,
    expected_binding: object | None = None,
    evidence_records: Mapping[str, EvidenceItem] | None = None,
    artifact_records: Mapping[str, ArtifactRecord] | None = None,
) -> dict[str, Any]:
    """Verify exact bounded audit bytes, hash chain, binding, and optional registry authority."""

    content_hash = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if len(raw) > _MAX_EVIDENCE_AUDIT_BYTES:
        return {
            "valid": False,
            "events": 0,
            "head_hash": "GENESIS",
            "content_hash": content_hash,
            "reason": "regulated audit log exceeds restore size bound",
        }
    binding: dict[str, Any] | None = None
    if expected_binding is not None:
        try:
            binding = validate_regulated_audit_binding(expected_binding)
        except ValueError as exc:
            return {
                "valid": False,
                "events": 0,
                "head_hash": "GENESIS",
                "content_hash": content_hash,
                "reason": str(exc),
            }

    expected_previous = "GENESIS"
    expected_sequence = 1
    evidence_hashes: dict[str, tuple[str, str | None]] = {}
    artifact_hashes: dict[str, str] = {}
    stream = io.BytesIO(raw)
    total_bytes = 0
    try:
        while True:
            raw_line = stream.readline(_MAX_EVIDENCE_AUDIT_LINE_BYTES + 1)
            if not raw_line:
                break
            total_bytes += len(raw_line)
            if total_bytes > _MAX_EVIDENCE_AUDIT_BYTES:
                raise ValueError("regulated audit log exceeds restore size bound")
            if len(raw_line) > _MAX_EVIDENCE_AUDIT_LINE_BYTES:
                raise ValueError("regulated audit event exceeds line-size bound")
            if not raw_line.strip():
                continue
            record = parse_json_object_strict(
                raw_line.decode("utf-8"),
                label="regulated audit event",
            )
            sequence = record.get("sequence")
            if type(sequence) is not int or sequence != expected_sequence:
                raise ValueError("regulated audit event sequence is invalid")
            if record.get("previous_hash") != expected_previous:
                raise ValueError("regulated audit previous-hash linkage is invalid")
            core = {key: value for key, value in record.items() if key != "event_hash"}
            calculated = _hash_json_bounded(
                core,
                max_bytes=_MAX_EVIDENCE_AUDIT_LINE_BYTES,
                label="regulated audit event core",
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
                default=str,
                preflight_default=str,
            )
            if record.get("event_hash") != calculated:
                raise ValueError("regulated audit event hash is invalid")
            payload = record.get("payload")
            event_type = record.get("event_type")
            if event_type in {"evidence_registered", "artifact_registered"}:
                if not isinstance(payload, dict):
                    raise ValueError("regulated audit registry event payload is invalid")
                if event_type == "evidence_registered":
                    evidence_id = payload.get("evidence_id")
                    content = payload.get("content_hash")
                    if (
                        not isinstance(evidence_id, str)
                        or not evidence_id
                        or not isinstance(content, str)
                    ):
                        raise ValueError("regulated audit evidence registration is invalid")
                    if evidence_id in evidence_hashes:
                        raise ValueError("regulated audit contains duplicate evidence registration")
                    raw_algorithm = payload.get("content_hash_algorithm")
                    algorithm = str(raw_algorithm) if raw_algorithm is not None else None
                    evidence_hashes[evidence_id] = (content, algorithm)
                else:
                    artifact_id = payload.get("artifact_id")
                    content = payload.get("content_hash")
                    if (
                        not isinstance(artifact_id, str)
                        or not artifact_id
                        or not isinstance(content, str)
                    ):
                        raise ValueError("regulated audit artifact registration is invalid")
                    if artifact_id in artifact_hashes:
                        raise ValueError("regulated audit contains duplicate artifact registration")
                    artifact_hashes[artifact_id] = content
            expected_previous = calculated
            expected_sequence += 1
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {
            "valid": False,
            "events": expected_sequence - 1,
            "head_hash": expected_previous,
            "content_hash": content_hash,
            "reason": str(exc),
        }

    events = expected_sequence - 1
    head_hash = expected_previous
    if binding is not None:
        if binding["events"] != events:
            return {
                "valid": False,
                "events": events,
                "head_hash": head_hash,
                "content_hash": content_hash,
                "reason": "regulated audit event count does not match manifest binding",
            }
        if binding["last_event_hash"] != head_hash:
            return {
                "valid": False,
                "events": events,
                "head_hash": head_hash,
                "content_hash": content_hash,
                "reason": "regulated audit head hash does not match manifest binding",
            }
        if binding["content_hash"] != content_hash:
            return {
                "valid": False,
                "events": events,
                "head_hash": head_hash,
                "content_hash": content_hash,
                "reason": "regulated audit content hash does not match manifest binding",
            }

    if evidence_records is not None:
        if set(evidence_hashes) != set(evidence_records):
            return {
                "valid": False,
                "events": events,
                "head_hash": head_hash,
                "content_hash": content_hash,
                "reason": "regulated evidence registry does not match audit log",
            }
        for evidence_id, evidence_item in evidence_records.items():
            expected_hash, algorithm = evidence_hashes[evidence_id]
            if algorithm is None:
                actual = _evidence_item_hash_for_audit(evidence_item, canonical=False)
            elif algorithm == _CANONICAL_EVIDENCE_HASH_ALGORITHM:
                actual = _evidence_item_hash_for_audit(evidence_item, canonical=True)
            else:
                return {
                    "valid": False,
                    "events": events,
                    "head_hash": head_hash,
                    "content_hash": content_hash,
                    "reason": f"regulated evidence hash algorithm is unsupported: {evidence_id}",
                }
            if expected_hash != actual:
                return {
                    "valid": False,
                    "events": events,
                    "head_hash": head_hash,
                    "content_hash": content_hash,
                    "reason": f"regulated evidence integrity check failed: {evidence_id}",
                }

    if artifact_records is not None:
        if set(artifact_hashes) != set(artifact_records):
            return {
                "valid": False,
                "events": events,
                "head_hash": head_hash,
                "content_hash": content_hash,
                "reason": "regulated artifact registry does not match audit log",
            }
        for artifact_id, artifact_record in artifact_records.items():
            if artifact_hashes[artifact_id] != artifact_record.content_hash:
                return {
                    "valid": False,
                    "events": events,
                    "head_hash": head_hash,
                    "content_hash": content_hash,
                    "reason": f"regulated artifact registry integrity check failed: {artifact_id}",
                }

    result: dict[str, Any] = {
        "valid": True,
        "events": events,
        "head_hash": head_hash,
        "content_hash": content_hash,
    }
    if evidence_records is not None or artifact_records is not None:
        result["registry_reconciled"] = True
    return result


class EvidenceStore:
    """Append-only evidence registry with hashing, manifests, and optional audit chaining."""

    def __init__(
        self,
        root: Path,
        run_id: str,
        *,
        regulated_mode: bool = False,
        expected_run_root_identity: tuple[int, int] | None = None,
    ) -> None:
        self.run_id = run_id
        self.regulated_mode = regulated_mode
        artifact_root = root.expanduser().resolve()
        requested_run = Path(run_id)
        if requested_run.is_absolute() or not requested_run.parts or ".." in requested_run.parts:
            raise ValueError("evidence run_id escapes artifact root")
        cursor = artifact_root
        for part in requested_run.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("evidence run_id contains a symlink and has ambiguous ownership")
        self.run_root = (artifact_root / requested_run).resolve()
        if self.run_root == artifact_root or artifact_root not in self.run_root.parents:
            raise ValueError("evidence run_id escapes artifact root")
        self.run_root.mkdir(parents=True, exist_ok=True)
        root_status = self.run_root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(root_status.st_mode):
            raise ValueError("evidence run root must remain a regular directory")
        self._descriptor_relative_root = descriptor_relative_authority_supported()
        self._run_root_identity = (
            pin_directory_identity(self.run_root, label="evidence run root")
            if self._descriptor_relative_root
            else _identity(root_status)
        )
        if (
            expected_run_root_identity is not None
            and self._run_root_identity != expected_run_root_identity
        ):
            raise ValueError("evidence run root does not match authorized run persistence root")
        self._assert_control_file_owned("evidence-manifest.json")
        self._assert_control_file_owned("audit-log.jsonl")
        self._items: dict[str, EvidenceItem] = {}
        self._artifacts: dict[str, ArtifactRecord] = {}
        self._audit_sequence = 0
        self._audit_previous_hash = "GENESIS"
        self._audit_content_hash: str | None = None
        self._audit_file_identity: tuple[int, int] | None = None
        self._manifest_audit_binding: dict[str, Any] | None = None
        self._audit_write_uncertain = False
        self._lock = threading.RLock()
        self._restore_manifest()
        if self.regulated_mode:
            self._restore_audit_tail()
            self._verify_artifact_hashes()
            self._verify_registry_against_audit()

    @property
    def run_root_identity(self) -> tuple[int, int]:
        """Return the exact run-persistence directory identity owned by this store."""

        return self._run_root_identity

    @staticmethod
    def hash_bytes(content: bytes) -> str:
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    @staticmethod
    def hash_file(path: Path, *, max_bytes: int, label: str) -> str:
        digest, _size = sha256_file_bounded(path, max_bytes=max_bytes, label=label)
        return f"sha256:{digest}"

    def _revalidate_run_root(self) -> None:
        try:
            current = self.run_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise ValueError(
                "evidence run root changed identity and ownership is ambiguous"
            ) from exc
        if not stat.S_ISDIR(current.st_mode) or _identity(current) != self._run_root_identity:
            raise ValueError("evidence run root changed identity and ownership is ambiguous")

    def _stat_owned_entry(self, relative_path: str, *, label: str) -> os.stat_result:
        self._revalidate_run_root()
        if self._descriptor_relative_root:
            return stat_confined_entry(
                self.run_root,
                relative_path,
                label=label,
                expected_root_identity=self._run_root_identity,
            )
        path = self._owned_artifact_path(relative_path)
        current = path.stat(follow_symlinks=False)
        self._revalidate_run_root()
        return current

    def _entry_exists(self, relative_path: str, *, label: str) -> bool:
        try:
            self._stat_owned_entry(relative_path, label=label)
        except FileNotFoundError:
            return False
        return True

    def _read_owned_bytes(self, relative_path: str, *, max_bytes: int, label: str) -> bytes:
        self._revalidate_run_root()
        if self._descriptor_relative_root:
            data = read_bytes_confined(
                self.run_root,
                relative_path,
                max_bytes=max_bytes,
                label=label,
                expected_root_identity=self._run_root_identity,
            )
            self._revalidate_run_root()
            return data
        path = self._owned_artifact_path(relative_path)
        with open_regular_binary(path, label=label) as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} byte ingestion limit")
        self._revalidate_run_root()
        return data

    def _read_audit_bytes(self) -> bytes:
        self._revalidate_run_root()
        if self._descriptor_relative_root:
            data = read_bytes_confined(
                self.run_root,
                "audit-log.jsonl",
                max_bytes=_MAX_EVIDENCE_AUDIT_BYTES,
                label="regulated audit log",
                expected_root_identity=self._run_root_identity,
                expected_entry_identity=self._audit_file_identity,
            )
            self._revalidate_run_root()
            return data
        return self._read_owned_bytes(
            "audit-log.jsonl",
            max_bytes=_MAX_EVIDENCE_AUDIT_BYTES,
            label="regulated audit log",
        )

    def _owned_file_hash(self, relative_path: str, *, max_bytes: int, label: str) -> str:
        if self._descriptor_relative_root:
            if self.regulated_mode and relative_path == "audit-log.jsonl":
                data = self._read_audit_bytes()
            else:
                data = self._read_owned_bytes(relative_path, max_bytes=max_bytes, label=label)
            return self.hash_bytes(data)
        path = self._owned_artifact_path(relative_path)
        return self.hash_file(path, max_bytes=max_bytes, label=label)

    def _assert_control_file_owned(self, name: str) -> Path:
        self._revalidate_run_root()
        path = self.run_root / name
        if self._descriptor_relative_root:
            try:
                current = stat_confined_entry(
                    self.run_root,
                    name,
                    label=f"evidence control file {name}",
                    expected_root_identity=self._run_root_identity,
                )
            except FileNotFoundError:
                return path
            if stat.S_ISLNK(current.st_mode):
                raise ValueError(
                    f"evidence control file is a symlink and has ambiguous ownership: {name}"
                )
            return path
        if path.is_symlink():
            raise ValueError(
                f"evidence control file is a symlink and has ambiguous ownership: {name}"
            )
        return path

    def _owned_artifact_path(self, relative_path: str) -> Path:
        self._revalidate_run_root()
        requested = Path(relative_path)
        if requested.is_absolute() or not requested.parts or ".." in requested.parts:
            raise ValueError("artifact path must be a non-traversing relative path under run root")
        if self._descriptor_relative_root:
            return self.run_root / requested
        cursor = self.run_root
        for part in requested.parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                raise ValueError("artifact path contains a symlink and has ambiguous ownership")
        destination = (self.run_root / requested).resolve()
        if self.run_root not in destination.parents:
            raise ValueError("artifact path escapes run root")
        return destination

    def _registered_artifact_bytes(self) -> int:
        total = 0
        for record in self._artifacts.values():
            try:
                current = self._stat_owned_entry(
                    record.path,
                    label=f"registered artifact {record.path}",
                )
            except FileNotFoundError as exc:
                raise ValueError(f"registered artifact is unavailable: {record.path}") from exc
            if not stat.S_ISREG(current.st_mode):
                raise ValueError(f"registered artifact is unavailable: {record.path}")
            size = current.st_size
            if size > _MAX_ARTIFACT_BYTES:
                raise ValueError(f"registered artifact exceeds persistence limit: {record.path}")
            total += size
            if total > _MAX_TOTAL_ARTIFACT_BYTES:
                raise ValueError("registered artifacts exceed cumulative persistence limit")
        return total

    def add(self, item: EvidenceItem) -> EvidenceItem:
        with self._lock:
            if item.run_id != self.run_id:
                raise ValueError("evidence run_id does not match store")
            self._assert_evidence_item_capacity(item)
            safe_payload = sanitize(item.model_dump(mode="json"))
            safe_item = EvidenceItem.model_validate(safe_payload)
            if safe_item.id in self._items:
                raise ValueError(f"evidence id is immutable and already registered: {safe_item.id}")
            if len(self._items) >= _MAX_EVIDENCE_COUNT:
                raise ValueError("evidence registry exceeds persistence count limit")

            audit_sequence_before = self._audit_sequence
            self._items[safe_item.id] = safe_item
            try:
                self._assert_manifest_capacity(
                    reserve_bytes=_MANIFEST_AUDIT_RESERVE_BYTES if self.regulated_mode else 0
                )
                self._append_audit_event(
                    "evidence_registered",
                    {
                        "evidence_id": safe_item.id,
                        "kind": safe_item.kind.value,
                        "content_hash": self._evidence_item_hash(safe_item, canonical=True),
                        "content_hash_algorithm": _CANONICAL_EVIDENCE_HASH_ALGORITHM,
                    },
                )
                self._flush_manifest()
            except BaseException:
                if self._audit_sequence == audit_sequence_before:
                    self._items.pop(safe_item.id, None)
                raise
            return safe_item

    def register_artifact(
        self,
        *,
        relative_path: str,
        content: bytes,
        originating_tool: str,
        sanitization_status: SanitizationStatus = SanitizationStatus.RAW,
        retention_classification: str | None = None,
    ) -> tuple[str, str]:
        with self._lock:
            if not isinstance(content, bytes):
                raise TypeError("artifact content must be bytes")
            if len(content) > _MAX_ARTIFACT_BYTES:
                raise ValueError(f"artifact exceeds {_MAX_ARTIFACT_BYTES} byte persistence limit")
            if len(self._artifacts) >= _MAX_ARTIFACT_COUNT:
                raise ValueError("artifact registry exceeds persistence count limit")
            if self._registered_artifact_bytes() + len(content) > _MAX_TOTAL_ARTIFACT_BYTES:
                raise ValueError("artifact registry exceeds cumulative persistence byte limit")

            destination = self._owned_artifact_path(relative_path)
            normalized_relative = Path(relative_path).as_posix()
            digest = self.hash_bytes(content)
            record = ArtifactRecord(
                type=destination.suffix.lstrip(".") or "binary",
                path=normalized_relative,
                originating_tool=originating_tool,
                content_hash=digest,
                sanitization_status=sanitization_status,
                retention_classification=(
                    retention_classification
                    if retention_classification is not None
                    else ("regulated" if self.regulated_mode else "standard")
                ),
            )
            if record.artifact_id in self._artifacts:
                raise ValueError("artifact id collision prevents deterministic registration")

            # Capacity failures are deterministic and must be rejected before bytes are published.
            self._artifacts[record.artifact_id] = record
            try:
                self._assert_manifest_capacity(
                    reserve_bytes=_MANIFEST_AUDIT_RESERVE_BYTES if self.regulated_mode else 0
                )
            finally:
                self._artifacts.pop(record.artifact_id, None)

            if self._descriptor_relative_root:
                try:
                    atomic_write_bytes_confined(
                        self.run_root,
                        normalized_relative,
                        content,
                        create_parents=True,
                        create_only=True,
                        label="evidence artifact",
                        expected_root_identity=self._run_root_identity,
                    )
                except FileExistsError:
                    raise FileExistsError(
                        f"artifact path is immutable and already exists: {relative_path}"
                    ) from None
                self._revalidate_run_root()
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    raise FileExistsError(
                        f"artifact path is immutable and already exists: {relative_path}"
                    )
                handle, raw_temp = tempfile.mkstemp(
                    dir=destination.parent, prefix=f".{destination.name}.", suffix=".artifact.tmp"
                )
                temp = Path(raw_temp)
                try:
                    with os.fdopen(handle, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.link(temp, destination)
                        fsync_directory(destination.parent)
                    except FileExistsError:
                        raise FileExistsError(
                            f"artifact path is immutable and already exists: {relative_path}"
                        ) from None
                finally:
                    temp.unlink(missing_ok=True)

            audit_sequence_before = self._audit_sequence
            self._artifacts[record.artifact_id] = record
            try:
                self._append_audit_event(
                    "artifact_registered",
                    {
                        "artifact_id": record.artifact_id,
                        "path": record.path,
                        "content_hash": record.content_hash,
                        "sanitization_status": record.sanitization_status.value,
                        "retention_classification": record.retention_classification,
                    },
                )
                self._flush_manifest()
            except BaseException:
                if self._audit_sequence == audit_sequence_before:
                    self._artifacts.pop(record.artifact_id, None)
                # Published bytes are intentionally never removed by pathname here. A closure
                # failure may coincide with parent replacement; deletion could otherwise target
                # bytes no longer owned by this transaction. Leave an orphan and fail closed.
                raise
            return record.path, digest

    def get(self, evidence_id: str) -> EvidenceItem:
        with self._lock:
            return self._items[evidence_id]

    def all(self) -> list[EvidenceItem]:
        with self._lock:
            return list(self._items.values())

    def _append_audit_event(self, event_type: str, payload: dict[str, Any]) -> None:
        if not self.regulated_mode:
            return
        if self._audit_write_uncertain:
            raise OSError("regulated audit log write state is uncertain")
        path = self._assert_control_file_owned("audit-log.jsonl")
        try:
            json_size_bounded(
                payload,
                max_bytes=_MAX_EVIDENCE_AUDIT_LINE_BYTES,
                label="regulated audit payload",
                sort_keys=True,
                ensure_ascii=True,
                default=str,
                preflight_default=str,
            )
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("regulated audit event exceeds line-size bound") from exc
            raise ValueError(
                f"regulated audit payload violates serialization bound: {exc.code}"
            ) from exc

        next_sequence = self._audit_sequence + 1
        timestamp = datetime.now(UTC).isoformat()
        core = {
            "sequence": next_sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "payload": sanitize(payload),
            "previous_hash": self._audit_previous_hash,
        }
        try:
            event_hash = _hash_json_bounded(
                core,
                max_bytes=_MAX_EVIDENCE_AUDIT_LINE_BYTES,
                label="regulated audit event core",
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
                default=str,
                preflight_default=str,
            )
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("regulated audit event exceeds line-size bound") from exc
            raise ValueError(
                f"regulated audit event violates serialization bound: {exc.code}"
            ) from exc

        record = {**core, "event_hash": event_hash}
        line_payload_limit = _MAX_EVIDENCE_AUDIT_LINE_BYTES - 1
        try:
            rendered_size = (
                json_size_bounded(
                    record,
                    max_bytes=line_payload_limit,
                    label="regulated audit event",
                    sort_keys=True,
                    ensure_ascii=True,
                    default=str,
                    preflight_default=str,
                )
                + 1
            )
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("regulated audit event exceeds line-size bound") from exc
            raise ValueError(
                f"regulated audit event violates serialization bound: {exc.code}"
            ) from exc

        if self._descriptor_relative_root:
            chunks: list[bytes] = []
            try:
                for chunk in iter_json_text_bounded(
                    record,
                    max_bytes=line_payload_limit,
                    label="regulated audit event",
                    sort_keys=True,
                    ensure_ascii=True,
                    default=str,
                    preflight_default=str,
                ):
                    chunks.append(chunk.encode("utf-8"))
            except JsonSerializationBoundsError as exc:
                if exc.code == "bytes":
                    raise ValueError("regulated audit event exceeds line-size bound") from exc
                raise ValueError(
                    f"regulated audit event violates serialization bound: {exc.code}"
                ) from exc
            rendered = b"".join(chunks) + b"\n"
            if len(rendered) != rendered_size:
                raise OSError("regulated audit serialization size changed between bounded passes")
            try:
                audit_identity = append_bytes_confined(
                    self.run_root,
                    "audit-log.jsonl",
                    rendered,
                    max_total_bytes=_MAX_EVIDENCE_AUDIT_BYTES,
                    label="regulated audit log",
                    expected_root_identity=self._run_root_identity,
                    expected_entry_identity=self._audit_file_identity,
                    require_missing=self._audit_file_identity is None,
                )
                self._revalidate_run_root()
            except (OSError, ValueError):
                self._audit_write_uncertain = True
                raise
            self._audit_file_identity = audit_identity
            self._audit_sequence = next_sequence
            self._audit_previous_hash = event_hash
            return

        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        try:
            fd = os.open(path, flags, 0o600)
        except OSError as exc:
            if nofollow and exc.errno == errno.ELOOP:
                raise ValueError("regulated audit log became a symlink during append") from exc
            raise
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("regulated audit log must remain a regular file")
            if opened.st_size + rendered_size > _MAX_EVIDENCE_AUDIT_BYTES:
                raise ValueError("regulated audit log exceeds persistence size bound")
            try:
                for chunk in iter_json_text_bounded(
                    record,
                    max_bytes=line_payload_limit,
                    label="regulated audit event",
                    sort_keys=True,
                    ensure_ascii=True,
                    default=str,
                    preflight_default=str,
                ):
                    _write_fd_all(fd, chunk.encode("utf-8"))
                _write_fd_all(fd, b"\n")
                os.fsync(fd)
            except BaseException:
                try:
                    os.ftruncate(fd, opened.st_size)
                    os.fsync(fd)
                    if os.fstat(fd).st_size != opened.st_size:
                        raise OSError(
                            errno.EIO,
                            "regulated audit rollback did not restore the prior length",
                        )
                except BaseException as rollback_exc:
                    self._audit_write_uncertain = True
                    raise OSError(
                        "regulated audit append failed and rollback could not be durably proven"
                    ) from rollback_exc
                raise
            if opened.st_size == 0:
                try:
                    fsync_directory(path.parent)
                except BaseException as directory_exc:
                    self._audit_write_uncertain = True
                    raise OSError(
                        "regulated audit log directory durability could not be proven"
                    ) from directory_exc
        finally:
            try:
                os.close(fd)
            except BaseException as close_exc:
                self._audit_write_uncertain = True
                raise OSError(
                    "regulated audit log descriptor close could not be proven"
                ) from close_exc
        self._audit_sequence = next_sequence
        self._audit_previous_hash = event_hash

    def _restore_manifest(self) -> None:
        path = self._assert_control_file_owned("evidence-manifest.json")
        if not self._entry_exists("evidence-manifest.json", label="evidence manifest"):
            return
        try:
            if self._descriptor_relative_root:
                rendered = self._read_owned_bytes(
                    "evidence-manifest.json",
                    max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                    label="evidence manifest",
                ).decode("utf-8")
                data = parse_json_object_strict(rendered, label="evidence manifest")
            else:
                data = read_json_object_bounded(
                    path,
                    max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                    label="evidence manifest",
                )
            if data.get("run_id") != self.run_id:
                raise ValueError("evidence manifest run_id mismatch")
            manifest_regulated = data.get("regulated_mode")
            if type(manifest_regulated) is not bool:
                raise ValueError("evidence manifest regulated_mode must be a boolean")
            if manifest_regulated != self.regulated_mode:
                raise ValueError("evidence manifest regulated_mode mismatch")
            if self.regulated_mode:
                self._manifest_audit_binding = validate_regulated_audit_binding(
                    data.get("audit_log")
                )
            raw_evidence = data.get("evidence", [])
            raw_artifacts = data.get("artifacts", [])
            if not isinstance(raw_evidence, list) or not isinstance(raw_artifacts, list):
                raise ValueError("evidence manifest registries must be lists")
            if len(raw_evidence) > _MAX_EVIDENCE_COUNT:
                raise ValueError("evidence manifest exceeds evidence count limit")
            if len(raw_artifacts) > _MAX_ARTIFACT_COUNT:
                raise ValueError("evidence manifest exceeds artifact count limit")
            evidence_records = [
                EvidenceItem.model_validate_json(json.dumps(raw), strict=True)
                for raw in raw_evidence
            ]
            artifact_records = [
                ArtifactRecord.model_validate_json(json.dumps(raw), strict=True)
                for raw in raw_artifacts
            ]
            if any(item.run_id != self.run_id for item in evidence_records):
                raise ValueError("evidence manifest contains evidence from another run")
            if len({item.id for item in evidence_records}) != len(evidence_records):
                raise ValueError("evidence manifest contains duplicate evidence ids")
            if len({item.artifact_id for item in artifact_records}) != len(artifact_records):
                raise ValueError("evidence manifest contains duplicate artifact ids")
            if len({item.path for item in artifact_records}) != len(artifact_records):
                raise ValueError("evidence manifest contains duplicate artifact paths")
            self._items = {item.id: item for item in evidence_records}
            self._artifacts = {item.artifact_id: item for item in artifact_records}
        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise ValueError("evidence manifest could not be restored") from exc

    def _iter_audit_records(self) -> Iterator[dict[str, Any]]:
        self._assert_control_file_owned("audit-log.jsonl")
        if not self._entry_exists("audit-log.jsonl", label="regulated audit log"):
            return
        raw = self._read_audit_bytes()
        stream: Any = io.BytesIO(raw)
        try:
            total_bytes = 0
            while True:
                raw_line = stream.readline(_MAX_EVIDENCE_AUDIT_LINE_BYTES + 1)
                if not raw_line:
                    break
                total_bytes += len(raw_line)
                if total_bytes > _MAX_EVIDENCE_AUDIT_BYTES:
                    raise ValueError("regulated audit log exceeds restore size bound")
                if len(raw_line) > _MAX_EVIDENCE_AUDIT_LINE_BYTES:
                    raise ValueError("regulated audit event exceeds line-size bound")
                if not raw_line.strip():
                    continue
                yield parse_json_object_strict(
                    raw_line.decode("utf-8"),
                    label="regulated audit event",
                )
        finally:
            stream.close()
            self._revalidate_run_root()

    def _verify_artifact_hashes(self) -> None:
        if len(self._artifacts) > _MAX_ARTIFACT_COUNT:
            raise ValueError("regulated artifact registry exceeds count limit")
        total = 0
        for record in self._artifacts.values():
            try:
                path = self._owned_artifact_path(record.path)
            except ValueError as exc:
                raise ValueError(
                    f"regulated artifact ownership check failed: {record.path}"
                ) from exc
            try:
                if self._descriptor_relative_root:
                    data = self._read_owned_bytes(
                        record.path,
                        max_bytes=_MAX_ARTIFACT_BYTES,
                        label=f"registered artifact {record.path}",
                    )
                    digest = hashlib.sha256(data).hexdigest()
                    size = len(data)
                else:
                    if not path.is_file():
                        raise ValueError(
                            f"regulated artifact is missing or escaped run root: {record.path}"
                        )
                    digest, size = sha256_file_bounded(
                        path,
                        max_bytes=_MAX_ARTIFACT_BYTES,
                        label=f"registered artifact {record.path}",
                    )
            except FileNotFoundError as exc:
                raise ValueError(
                    f"regulated artifact is missing or escaped run root: {record.path}"
                ) from exc
            except ValueError as exc:
                if "symlink" in str(exc) or "parent component" in str(exc):
                    raise ValueError(
                        f"regulated artifact ownership check failed: {record.path}"
                    ) from exc
                raise ValueError(
                    f"regulated artifact exceeds persistence limit: {record.path}"
                ) from exc
            total += size
            if total > _MAX_TOTAL_ARTIFACT_BYTES:
                raise ValueError("regulated artifacts exceed cumulative persistence limit")
            if f"sha256:{digest}" != record.content_hash:
                raise ValueError(f"regulated artifact integrity check failed: {record.path}")

    def _current_audit_status(
        self,
        *,
        expected_binding: object | None = None,
        reconcile_registry: bool = False,
    ) -> dict[str, Any]:
        if not self._entry_exists("audit-log.jsonl", label="regulated audit log"):
            return {
                "valid": False,
                "events": 0,
                "head_hash": "GENESIS",
                "content_hash": None,
                "reason": "regulated audit log is missing",
            }
        raw = self._read_audit_bytes()
        return verify_regulated_audit_subject(
            raw,
            expected_binding=expected_binding,
            evidence_records=self._items if reconcile_registry else None,
            artifact_records=self._artifacts if reconcile_registry else None,
        )

    def _verify_registry_against_audit(self) -> None:
        if not self._entry_exists("audit-log.jsonl", label="regulated audit log"):
            if self._items or self._artifacts:
                raise ValueError("regulated registry exists without audit log")
            return
        status = self._current_audit_status(reconcile_registry=True)
        if not status.get("valid"):
            raise ValueError(
                str(status.get("reason") or "regulated registry audit reconciliation failed")
            )

    def verify_audit_chain(self) -> bool:
        """Verify the current regulated audit subject against its pinned file identity."""
        with self._lock:
            if not self._entry_exists("audit-log.jsonl", label="regulated audit log"):
                return self._audit_sequence == 0 and self._audit_previous_hash == "GENESIS"
            try:
                status = self._current_audit_status()
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                return False
            return bool(status.get("valid"))

    def _restore_audit_tail(self) -> None:
        manifest_exists = self._entry_exists("evidence-manifest.json", label="evidence manifest")
        audit_exists = self._entry_exists("audit-log.jsonl", label="regulated audit log")
        if not audit_exists:
            if manifest_exists:
                raise ValueError("regulated evidence manifest exists without audit log")
            return
        if self._descriptor_relative_root:
            current = self._stat_owned_entry(
                "audit-log.jsonl",
                label="regulated audit log",
            )
            if not stat.S_ISREG(current.st_mode):
                raise ValueError("regulated audit log must remain a regular file")
            self._audit_file_identity = _identity(current)
        if self._manifest_audit_binding is None:
            status = self._current_audit_status()
            empty_hash = f"sha256:{hashlib.sha256(b'').hexdigest()}"
            if (
                status.get("valid")
                and status.get("events") == 0
                and status.get("head_hash") == "GENESIS"
                and status.get("content_hash") == empty_hash
                and not self._items
                and not self._artifacts
            ):
                self._audit_content_hash = empty_hash
                return
            raise ValueError("regulated evidence registry does not match audit log")
        status = self._current_audit_status(
            expected_binding=self._manifest_audit_binding,
            reconcile_registry=True,
        )
        if not status.get("valid"):
            raise ValueError(
                "regulated audit log integrity check failed: "
                + str(status.get("reason") or "unknown audit integrity failure")
            )
        self._audit_sequence = int(status["events"])
        self._audit_previous_hash = str(status["head_hash"])
        self._audit_content_hash = str(status["content_hash"])

    @staticmethod
    def _manifest_json_default(value: Any) -> Any:
        if isinstance(value, _RegistryFieldValue):
            payload = value.model.model_dump(include={value.name}, mode="json")
            return payload[value.name]
        if isinstance(value, BaseModel):
            return _registry_model_proxy(value)
        raise TypeError(f"unsupported evidence manifest value: {type(value).__name__}")

    @staticmethod
    def _manifest_json_preflight_default(value: Any) -> Any:
        if isinstance(value, _RegistryFieldValue):
            return getattr(value.model, value.name)
        if isinstance(value, BaseModel):
            return _registry_model_proxy(value)
        return json_preflight_scalar_default(value)

    def _evidence_item_hash(self, item: EvidenceItem, *, canonical: bool) -> str:
        return _hash_json_bounded(
            _registry_model_proxy(item),
            max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
            label="regulated evidence item hash",
            sort_keys=canonical,
            ensure_ascii=False,
            separators=(",", ":"),
            default=self._manifest_json_default,
            preflight_default=self._manifest_json_preflight_default,
        )

    def _assert_evidence_item_capacity(self, item: EvidenceItem) -> None:
        try:
            json_size_bounded(
                _registry_model_proxy(item),
                max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                label="evidence item",
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                default=self._manifest_json_default,
                preflight_default=self._manifest_json_preflight_default,
            )
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("evidence item exceeds persistence size bound") from exc
            raise ValueError(
                f"evidence item violates persistence serialization bound: {exc.code}"
            ) from exc

    def _manifest_data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "regulated_mode": self.regulated_mode,
            "evidence": list(self._items.values()),
            "artifacts": list(self._artifacts.values()),
            "sanitization_status": SanitizationStatus.SANITIZED.value,
        }
        if self.regulated_mode:
            data["audit_log"] = {
                "path": "audit-log.jsonl",
                "events": self._audit_sequence,
                "last_event_hash": self._audit_previous_hash,
                "content_hash": self._audit_content_hash,
            }
        return data

    def _assert_manifest_capacity(self, *, reserve_bytes: int = 0) -> None:
        if type(reserve_bytes) is not int or reserve_bytes < 0:
            raise ValueError("manifest reserve_bytes must be a non-negative integer")
        available = _MAX_EVIDENCE_MANIFEST_BYTES - reserve_bytes
        if available < 1:
            raise ValueError("evidence manifest exceeds persistence size bound")
        try:
            json_size_bounded(
                self._manifest_data(),
                max_bytes=available,
                label="evidence manifest",
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                default=self._manifest_json_default,
                preflight_default=self._manifest_json_preflight_default,
            )
        except JsonSerializationBoundsError as exc:
            if exc.code == "bytes":
                raise ValueError("evidence manifest exceeds persistence size bound") from exc
            raise ValueError(
                f"evidence manifest violates persistence serialization bound: {exc.code}"
            ) from exc

    def _flush_manifest(self) -> None:
        self._assert_control_file_owned("evidence-manifest.json")
        audit_binding: dict[str, Any] | None = None
        if self.regulated_mode:
            if self._audit_write_uncertain:
                raise OSError("regulated audit log write state is uncertain")
            try:
                audit_status = self._current_audit_status(reconcile_registry=True)
                if not audit_status.get("valid"):
                    raise ValueError(
                        str(audit_status.get("reason") or "regulated audit closure is invalid")
                    )
                if (
                    audit_status.get("events") != self._audit_sequence
                    or audit_status.get("head_hash") != self._audit_previous_hash
                ):
                    raise ValueError(
                        "regulated audit persisted tail does not match in-memory authority"
                    )
                self._audit_content_hash = str(audit_status["content_hash"])
                audit_binding = validate_regulated_audit_binding(self._manifest_data()["audit_log"])
            except BaseException:
                self._audit_write_uncertain = True
                raise

        data = self._manifest_data()
        try:
            if self._descriptor_relative_root:
                chunks: list[bytes] = []
                try:
                    for chunk in iter_json_text_bounded(
                        data,
                        max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                        label="evidence manifest",
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=True,
                        default=self._manifest_json_default,
                        preflight_default=self._manifest_json_preflight_default,
                    ):
                        chunks.append(chunk.encode("utf-8"))
                except JsonSerializationBoundsError as exc:
                    if exc.code == "bytes":
                        raise ValueError(
                            "evidence manifest exceeds persistence size bound"
                        ) from exc
                    raise ValueError(
                        f"evidence manifest violates persistence serialization bound: {exc.code}"
                    ) from exc
                atomic_write_bytes_confined(
                    self.run_root,
                    "evidence-manifest.json",
                    b"".join(chunks),
                    create_parents=False,
                    create_only=False,
                    label="evidence manifest",
                    expected_root_identity=self._run_root_identity,
                )
                self._revalidate_run_root()
            else:
                path = self.run_root / "evidence-manifest.json"
                handle, raw_temp = tempfile.mkstemp(
                    dir=self.run_root, prefix=".evidence-manifest.", suffix=".tmp", text=True
                )
                temp = Path(raw_temp)
                try:
                    with os.fdopen(handle, "w", encoding="utf-8") as stream:
                        try:
                            for chunk in iter_json_text_bounded(
                                data,
                                max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                                label="evidence manifest",
                                indent=2,
                                sort_keys=True,
                                ensure_ascii=True,
                                default=self._manifest_json_default,
                                preflight_default=self._manifest_json_preflight_default,
                            ):
                                stream.write(chunk)
                        except JsonSerializationBoundsError as exc:
                            if exc.code == "bytes":
                                raise ValueError(
                                    "evidence manifest exceeds persistence size bound"
                                ) from exc
                            raise ValueError(
                                f"evidence manifest violates persistence serialization bound: {exc.code}"
                            ) from exc
                        stream.flush()
                        os.fsync(stream.fileno())
                    temp.replace(path)
                    fsync_directory(path.parent)
                    self._revalidate_run_root()
                finally:
                    temp.unlink(missing_ok=True)

            if self.regulated_mode:
                post_status = self._current_audit_status(
                    expected_binding=audit_binding,
                    reconcile_registry=True,
                )
                if not post_status.get("valid"):
                    raise ValueError(
                        "regulated audit changed during manifest closure: "
                        + str(post_status.get("reason") or "unknown audit integrity failure")
                    )
                self._audit_content_hash = str(post_status["content_hash"])
                self._manifest_audit_binding = dict(audit_binding or {})
        except BaseException:
            if self.regulated_mode:
                self._audit_write_uncertain = True
            raise
