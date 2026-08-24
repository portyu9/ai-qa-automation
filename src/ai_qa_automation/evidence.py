from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
import tempfile
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .io_safety import (
    fsync_directory,
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


class EvidenceStore:
    """Append-only evidence registry with hashing, manifests, and optional audit chaining."""

    def __init__(self, root: Path, run_id: str, *, regulated_mode: bool = False) -> None:
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
        self._assert_control_file_owned("evidence-manifest.json")
        self._assert_control_file_owned("audit-log.jsonl")
        self._items: dict[str, EvidenceItem] = {}
        self._artifacts: dict[str, ArtifactRecord] = {}
        self._audit_sequence = 0
        self._audit_previous_hash = "GENESIS"
        self._lock = threading.RLock()
        self._restore_manifest()
        if self.regulated_mode:
            self._restore_audit_tail()
            self._verify_artifact_hashes()
            self._verify_registry_against_audit()

    @staticmethod
    def hash_bytes(content: bytes) -> str:
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    @staticmethod
    def hash_file(path: Path, *, max_bytes: int, label: str) -> str:
        digest, _size = sha256_file_bounded(path, max_bytes=max_bytes, label=label)
        return f"sha256:{digest}"

    def _assert_control_file_owned(self, name: str) -> Path:
        path = self.run_root / name
        if path.is_symlink():
            raise ValueError(
                f"evidence control file is a symlink and has ambiguous ownership: {name}"
            )
        return path

    def _owned_artifact_path(self, relative_path: str) -> Path:
        requested = Path(relative_path)
        if requested.is_absolute() or not requested.parts or ".." in requested.parts:
            raise ValueError("artifact path must be a non-traversing relative path under run root")
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
            path = self._owned_artifact_path(record.path)
            if not path.is_file():
                raise ValueError(f"registered artifact is unavailable: {record.path}")
            size = path.stat().st_size
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
                        "content_hash": self.hash_bytes(
                            safe_item.model_dump_json().encode("utf-8")
                        ),
                    },
                )
                self._flush_manifest()
            except Exception:
                # If no audit record was durably appended, the staged in-memory item is
                # not authoritative and can be removed safely. If the audit advanced but
                # manifest persistence failed, retain the item so live state still agrees
                # with the append-only audit record; reopening will fail closed until the
                # manifest is repaired/reconciled rather than pretending the event vanished.
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

            digest = self.hash_bytes(content)
            record = ArtifactRecord(
                type=destination.suffix.lstrip(".") or "binary",
                path=destination.relative_to(self.run_root).as_posix(),
                originating_tool=originating_tool,
                content_hash=digest,
                sanitization_status=sanitization_status,
                retention_classification=(
                    retention_classification
                    if retention_classification is not None
                    else ("regulated" if self.regulated_mode else "standard")
                ),
            )
            audit_sequence_before = self._audit_sequence
            self._artifacts[record.artifact_id] = record
            try:
                self._assert_manifest_capacity(
                    reserve_bytes=_MANIFEST_AUDIT_RESERVE_BYTES if self.regulated_mode else 0
                )
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
            except Exception:
                if self._audit_sequence == audit_sequence_before:
                    self._artifacts.pop(record.artifact_id, None)
                    destination.unlink(missing_ok=True)
                    fsync_directory(destination.parent)
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
        path = self._assert_control_file_owned("audit-log.jsonl")
        next_sequence = self._audit_sequence + 1
        timestamp = datetime.now(UTC).isoformat()
        core = {
            "sequence": next_sequence,
            "timestamp": timestamp,
            "event_type": event_type,
            "payload": sanitize(payload),
            "previous_hash": self._audit_previous_hash,
        }
        canonical = json.dumps(core, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
        event_hash = self.hash_bytes(canonical)
        record = {**core, "event_hash": event_hash}
        rendered = json.dumps(record, sort_keys=True, default=str) + "\n"
        rendered_bytes = rendered.encode("utf-8")
        if len(rendered_bytes) > _MAX_EVIDENCE_AUDIT_LINE_BYTES:
            raise ValueError("regulated audit event exceeds line-size bound")

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
            if opened.st_size + len(rendered_bytes) > _MAX_EVIDENCE_AUDIT_BYTES:
                raise ValueError("regulated audit log exceeds persistence size bound")
            with os.fdopen(fd, "a", encoding="utf-8") as stream:
                fd = -1
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            if opened.st_size == 0:
                fsync_directory(path.parent)
        finally:
            if fd >= 0:
                os.close(fd)
        self._audit_sequence = next_sequence
        self._audit_previous_hash = event_hash

    def _restore_manifest(self) -> None:
        path = self._assert_control_file_owned("evidence-manifest.json")
        if not path.exists():
            return
        try:
            data = read_json_object_bounded(
                path,
                max_bytes=_MAX_EVIDENCE_MANIFEST_BYTES,
                label="evidence manifest",
            )
            if data.get("run_id") != self.run_id:
                raise ValueError("evidence manifest run_id mismatch")
            manifest_regulated = bool(data.get("regulated_mode", False))
            if manifest_regulated != self.regulated_mode:
                raise ValueError("evidence manifest regulated_mode mismatch")
            raw_evidence = data.get("evidence", [])
            raw_artifacts = data.get("artifacts", [])
            if not isinstance(raw_evidence, list) or not isinstance(raw_artifacts, list):
                raise ValueError("evidence manifest registries must be lists")
            if len(raw_evidence) > _MAX_EVIDENCE_COUNT:
                raise ValueError("evidence manifest exceeds evidence count limit")
            if len(raw_artifacts) > _MAX_ARTIFACT_COUNT:
                raise ValueError("evidence manifest exceeds artifact count limit")
            evidence_records = [EvidenceItem.model_validate(raw) for raw in raw_evidence]
            artifact_records = [ArtifactRecord.model_validate(raw) for raw in raw_artifacts]
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
        path = self._assert_control_file_owned("audit-log.jsonl")
        if not path.exists():
            return
        if path.stat().st_size > _MAX_EVIDENCE_AUDIT_BYTES:
            raise ValueError("regulated audit log exceeds restore size bound")
        with open_regular_binary(path, label="regulated audit log") as stream:
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
            if not path.is_file():
                raise ValueError(
                    f"regulated artifact is missing or escaped run root: {record.path}"
                )
            try:
                digest, size = sha256_file_bounded(
                    path,
                    max_bytes=_MAX_ARTIFACT_BYTES,
                    label=f"registered artifact {record.path}",
                )
            except ValueError as exc:
                raise ValueError(
                    f"regulated artifact exceeds persistence limit: {record.path}"
                ) from exc
            total += size
            if total > _MAX_TOTAL_ARTIFACT_BYTES:
                raise ValueError("regulated artifacts exceed cumulative persistence limit")
            if f"sha256:{digest}" != record.content_hash:
                raise ValueError(f"regulated artifact integrity check failed: {record.path}")

    def _verify_registry_against_audit(self) -> None:
        path = self._assert_control_file_owned("audit-log.jsonl")
        if not path.exists():
            if self._items or self._artifacts:
                raise ValueError("regulated registry exists without audit log")
            return

        evidence_hashes: dict[str, str] = {}
        artifact_hashes: dict[str, str] = {}
        for record in self._iter_audit_records():
            payload = record.get("payload") or {}
            if record.get("event_type") == "evidence_registered":
                evidence_hashes[str(payload.get("evidence_id"))] = str(payload.get("content_hash"))
            elif record.get("event_type") == "artifact_registered":
                artifact_hashes[str(payload.get("artifact_id"))] = str(payload.get("content_hash"))

        if set(evidence_hashes) != set(self._items):
            raise ValueError("regulated evidence registry does not match audit log")
        if set(artifact_hashes) != set(self._artifacts):
            raise ValueError("regulated artifact registry does not match audit log")

        for evidence_id, evidence_item in self._items.items():
            actual = self.hash_bytes(evidence_item.model_dump_json().encode("utf-8"))
            if evidence_hashes[evidence_id] != actual:
                raise ValueError(f"regulated evidence integrity check failed: {evidence_id}")
        for artifact_id, artifact_record in self._artifacts.items():
            if artifact_hashes[artifact_id] != artifact_record.content_hash:
                raise ValueError(
                    f"regulated artifact registry integrity check failed: {artifact_id}"
                )

    def verify_audit_chain(self) -> bool:
        """Verify sequence, previous-hash linkage, and each regulated audit event hash."""
        with self._lock:
            path = self._assert_control_file_owned("audit-log.jsonl")
            if not path.exists():
                return self._audit_sequence == 0 and self._audit_previous_hash == "GENESIS"

            expected_previous = "GENESIS"
            expected_sequence = 1
            try:
                for record in self._iter_audit_records():
                    if int(record.get("sequence", -1)) != expected_sequence:
                        return False
                    if record.get("previous_hash") != expected_previous:
                        return False
                    core = {key: value for key, value in record.items() if key != "event_hash"}
                    canonical = json.dumps(
                        core, sort_keys=True, separators=(",", ":"), default=str
                    ).encode("utf-8")
                    calculated = self.hash_bytes(canonical)
                    if record.get("event_hash") != calculated:
                        return False
                    expected_previous = calculated
                    expected_sequence += 1
            except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                return False
            return True

    def _restore_audit_tail(self) -> None:
        path = self._assert_control_file_owned("audit-log.jsonl")
        if not path.exists():
            return
        if not self.verify_audit_chain():
            raise ValueError("regulated audit log integrity check failed")
        last: dict[str, Any] | None = None
        for record in self._iter_audit_records():
            last = record
        if last is None:
            return
        self._audit_sequence = int(last["sequence"])
        self._audit_previous_hash = str(last["event_hash"])

    def _manifest_data(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "run_id": self.run_id,
            "regulated_mode": self.regulated_mode,
            "evidence": [item.model_dump(mode="json") for item in self._items.values()],
            "artifacts": [item.model_dump(mode="json") for item in self._artifacts.values()],
            "sanitization_status": SanitizationStatus.SANITIZED,
        }
        if self.regulated_mode:
            audit_path = self._assert_control_file_owned("audit-log.jsonl")
            data["audit_log"] = {
                "path": audit_path.name,
                "events": self._audit_sequence,
                "last_event_hash": self._audit_previous_hash,
                "content_hash": (
                    self.hash_file(
                        audit_path,
                        max_bytes=_MAX_EVIDENCE_AUDIT_BYTES,
                        label="regulated audit log",
                    )
                    if audit_path.exists()
                    else None
                ),
            }
        return data

    def _render_manifest(self) -> str:
        return json.dumps(self._manifest_data(), indent=2, sort_keys=True)

    def _assert_manifest_capacity(self, *, reserve_bytes: int = 0) -> None:
        rendered_bytes = len(self._render_manifest().encode("utf-8"))
        if rendered_bytes + reserve_bytes > _MAX_EVIDENCE_MANIFEST_BYTES:
            raise ValueError("evidence manifest exceeds persistence size bound")

    def _flush_manifest(self) -> None:
        path = self._assert_control_file_owned("evidence-manifest.json")
        rendered = self._render_manifest()
        if len(rendered.encode("utf-8")) > _MAX_EVIDENCE_MANIFEST_BYTES:
            raise ValueError("evidence manifest exceeds persistence size bound")
        handle, raw_temp = tempfile.mkstemp(
            dir=self.run_root, prefix=".evidence-manifest.", suffix=".tmp", text=True
        )
        temp = Path(raw_temp)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            temp.replace(path)
            fsync_directory(path.parent)
        finally:
            temp.unlink(missing_ok=True)
