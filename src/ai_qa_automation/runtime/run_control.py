from __future__ import annotations

import hashlib
import json
import os
import tempfile
from _thread import RLock
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..io_safety import fsync_directory, read_bytes_bounded
from .budget import BudgetExceededError, ExecutionBudget
from .journal import RunJournal

_MAX_ROLLBACK_BYTES = 2_000_000
_MAX_RUNTIME_METADATA_BYTES = 2_000_000


class CircuitOpenError(RuntimeError):
    """Raised when a repeatedly failing tool circuit has opened."""


class MutationPendingError(RuntimeError):
    """Raised when a second mutation is attempted before validation closes the first."""


@dataclass(frozen=True)
class PendingMutation:
    relative_path: str
    existed: bool
    backup_path: str | None
    original_sha256: str | None
    change_revision_before: int | None = None


@dataclass
class RuntimeControl:
    """Operational state kept separate from canonical QA decision state."""

    workspace: Path
    budget: ExecutionBudget
    journal: RunJournal
    metadata_path: Path
    lease_id: str
    expected_workspace_fingerprint: str | None = None
    circuit_failure_threshold: int = 3
    circuit_failures: dict[str, int] = field(default_factory=dict)
    open_circuits: set[str] = field(default_factory=set)
    pending_mutation: PendingMutation | None = None
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.circuit_failure_threshold) is not int or self.circuit_failure_threshold < 1:
            raise ValueError("circuit_failure_threshold must be a positive integer")
        self.workspace = self.workspace.expanduser().resolve()
        self.metadata_path = self.metadata_path.expanduser()

    def before_tool(self, tool_name: str) -> None:
        with self._lock:
            if tool_name in self.open_circuits:
                raise CircuitOpenError(f"tool circuit is open after repeated failures: {tool_name}")

    def record_tool_result(self, tool_name: str, *, failed: bool) -> None:
        with self._lock:
            if failed:
                failures = self.circuit_failures.get(tool_name, 0) + 1
                self.circuit_failures[tool_name] = failures
                if failures >= self.circuit_failure_threshold:
                    self.open_circuits.add(tool_name)
            else:
                self.circuit_failures.pop(tool_name, None)
                self.open_circuits.discard(tool_name)
            self.persist()

    def prepare_mutation(
        self,
        relative_path: str,
        *,
        change_revision_before: int | None = None,
    ) -> None:
        with self._lock:
            if self.pending_mutation is not None:
                raise MutationPendingError(
                    f"a mutation is already pending validation: {self.pending_mutation.relative_path}"
                )
            target = self._target(relative_path)
            rollback_root = self.metadata_path.parent / "rollback"
            if rollback_root.is_symlink():
                raise MutationPendingError(
                    "rollback directory is a symlink and has ambiguous ownership"
                )
            rollback_root.mkdir(parents=True, exist_ok=True)
            rollback_root = rollback_root.resolve()
            existed = target.exists()
            backup_path: Path | None = None
            original_hash: str | None = None
            if existed:
                if not target.is_file():
                    raise MutationPendingError("mutation target must be a regular file")
                try:
                    data = read_bytes_bounded(
                        target,
                        max_bytes=_MAX_ROLLBACK_BYTES,
                        label="mutation target",
                    )
                except ValueError as exc:
                    raise MutationPendingError(
                        "mutation target exceeds 2 MB rollback safety limit"
                    ) from exc
                original_hash = hashlib.sha256(data).hexdigest()
                backup_path = rollback_root / (
                    f"{hashlib.sha256(relative_path.encode()).hexdigest()[:24]}.bin"
                )
                _atomic_write_bytes(backup_path, data)

            pending = PendingMutation(
                relative_path=relative_path,
                existed=existed,
                backup_path=str(backup_path) if backup_path else None,
                original_sha256=original_hash,
                change_revision_before=change_revision_before,
            )
            self.pending_mutation = pending
            pending_persisted = False
            try:
                # Durable runtime metadata is the recovery authority. Persist the pending
                # transaction before allowing the target mutation tool to execute.
                self.persist()
                pending_persisted = True
                self.journal.append(
                    "mutation_prepared",
                    path=relative_path,
                    existed=existed,
                    original_sha256=original_hash,
                    change_revision_before=change_revision_before,
                )
            except Exception:
                self.pending_mutation = None
                if pending_persisted:
                    try:
                        self.persist()
                    except Exception as cleanup_exc:
                        # The durable metadata may still describe a pending transaction.
                        # Keep the live object aligned with that conservative state so a
                        # later finalizer/recovery path cannot assume preparation vanished.
                        self.pending_mutation = pending
                        raise RuntimeError(
                            "mutation preparation failed and pending metadata could not be cleared"
                        ) from cleanup_exc
                if backup_path is not None:
                    with suppress(OSError):
                        backup_path.unlink(missing_ok=True)
                raise

    def commit_pending_mutation(self) -> str | None:
        with self._lock:
            pending = self.pending_mutation
            if pending is None:
                return None
            backup: Path | None = None
            if pending.existed:
                backup, _ = self._validated_rollback_backup(pending)

            # Commit authority becomes durable by clearing pending metadata first. Only
            # after that succeeds may the rollback snapshot be discarded. A crash after
            # metadata persistence can at worst leave an orphan backup, never a committed
            # target whose only rollback bytes were deleted while metadata still said pending.
            self.pending_mutation = None
            try:
                self.persist()
            except Exception:
                self.pending_mutation = pending
                raise

            cleanup_failed = False
            if backup is not None:
                try:
                    backup.unlink()
                except OSError:
                    cleanup_failed = True
            self._journal_after_durable_transition(
                "mutation_committed",
                path=pending.relative_path,
                rollback_cleanup_failed=cleanup_failed,
            )
            return pending.relative_path

    def rollback_pending_mutation(self, *, reason: str) -> str | None:
        with self._lock:
            pending = self.pending_mutation
            if pending is None:
                return None
            target = self._target(pending.relative_path)
            backup: Path | None = None
            if pending.existed:
                backup, data = self._validated_rollback_backup(pending)
                target.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write_bytes(target, data)
            else:
                target.unlink(missing_ok=True)
                # A prepared new-file mutation may be cancelled before its parent
                # directory or target is ever created. In that case no directory entry
                # changed, so there is nothing to flush. If the parent exists, fsync it
                # to durably persist removal of an actually-created target.
                if target.parent.is_dir():
                    fsync_directory(target.parent)

            # The target bytes are now restored/removed. Persist closure before deleting
            # the rollback snapshot. If metadata persistence fails, keep the transaction
            # pending and the backup intact so recovery remains conservative.
            self.pending_mutation = None
            try:
                self.persist()
            except Exception:
                self.pending_mutation = pending
                raise

            cleanup_failed = False
            if backup is not None:
                try:
                    backup.unlink()
                except OSError:
                    cleanup_failed = True
            self._journal_after_durable_transition(
                "mutation_rolled_back",
                path=pending.relative_path,
                reason=reason,
                rollback_cleanup_failed=cleanup_failed,
            )
            return pending.relative_path

    def _journal_after_durable_transition(self, event: str, **payload: Any) -> None:
        """Record lifecycle provenance without undoing an already-durable transition."""
        try:
            self.journal.append(event, **payload)
        except (BudgetExceededError, OSError, RuntimeError, ValueError):
            # Runtime metadata already owns the transaction truth at this point.
            # A journal failure must not resurrect pending state or destroy restored
            # bytes. The journal verifier will expose any persisted integrity issue.
            return

    def _validated_rollback_backup(self, pending: PendingMutation) -> tuple[Path, bytes]:
        """Validate rollback ownership and bytes before either restore or commit disposal."""
        if not pending.backup_path or not pending.original_sha256:
            raise RuntimeError("pending rollback backup metadata is incomplete")

        raw_rollback_root = (self.metadata_path.parent / "rollback").expanduser()
        if raw_rollback_root.is_symlink():
            raise RuntimeError("rollback directory is a symlink and has ambiguous ownership")
        rollback_root = raw_rollback_root.resolve()
        raw_backup = Path(pending.backup_path).expanduser()
        absolute_backup = raw_backup if raw_backup.is_absolute() else raw_backup.absolute()
        try:
            relative = absolute_backup.relative_to(rollback_root)
        except ValueError as exc:
            raise RuntimeError("pending rollback backup escaped rollback directory") from exc
        if relative == Path():
            raise RuntimeError("pending rollback backup cannot be the rollback directory")

        cursor = rollback_root
        for part in relative.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                raise RuntimeError("pending rollback backup contains a symlink")

        backup = absolute_backup.resolve()
        try:
            backup.relative_to(rollback_root)
        except ValueError as exc:
            raise RuntimeError("pending rollback backup escaped rollback directory") from exc
        if not backup.is_file():
            raise RuntimeError("pending rollback backup is missing or not a regular file")
        try:
            data = read_bytes_bounded(
                backup,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="pending rollback backup",
            )
        except ValueError as exc:
            raise RuntimeError("pending rollback backup exceeds 2 MB safety limit") from exc
        if hashlib.sha256(data).hexdigest() != pending.original_sha256:
            raise RuntimeError("pending rollback backup failed integrity verification")
        return backup, data

    def set_workspace_fingerprint(self, fingerprint: str) -> None:
        with self._lock:
            self.expected_workspace_fingerprint = fingerprint
            self.persist()

    def persist(self) -> None:
        with self._lock:
            atomic_write_json(self.metadata_path, self.snapshot(include_pending_details=True))

    def snapshot(self, *, include_pending_details: bool = False) -> dict[str, Any]:
        with self._lock:
            pending: object = None
            if self.pending_mutation:
                pending = (
                    {
                        "relative_path": self.pending_mutation.relative_path,
                        "existed": self.pending_mutation.existed,
                        "backup_path": self.pending_mutation.backup_path,
                        "original_sha256": self.pending_mutation.original_sha256,
                        "change_revision_before": self.pending_mutation.change_revision_before,
                    }
                    if include_pending_details
                    else self.pending_mutation.relative_path
                )
            return {
                "lease_id": self.lease_id,
                "workspace": str(self.workspace),
                "workspace_fingerprint": self.expected_workspace_fingerprint,
                "budget": self.budget.snapshot().as_dict(),
                "journal_event_count": self.journal.event_count,
                "journal_head_hash": self.journal.head_hash,
                "circuit_failures": dict(sorted(self.circuit_failures.items())),
                "open_circuits": sorted(self.open_circuits),
                "pending_mutation": pending,
                "updated_at": datetime.now(UTC).isoformat(),
            }

    def _target(self, relative_path: str) -> Path:
        requested = Path(relative_path)
        if requested.is_absolute() or ".." in requested.parts:
            raise MutationPendingError("mutation path escapes the target workspace")

        cursor = self.workspace
        for part in requested.parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                raise MutationPendingError(
                    "mutation path contains a symlink and has ambiguous ownership"
                )

        target = (self.workspace / requested).resolve()
        try:
            target.relative_to(self.workspace)
        except ValueError as exc:
            raise MutationPendingError("mutation path escapes the target workspace") from exc
        return target


def _owned_atomic_target(path: Path) -> Path:
    """Resolve an owned parent without ever following a symlink at the write target."""
    requested = path.expanduser()
    if requested.is_symlink():
        raise RuntimeError("atomic write target is a symlink and has ambiguous ownership")
    raw_parent = requested.parent
    if raw_parent.is_symlink():
        raise RuntimeError("atomic write parent is a symlink and has ambiguous ownership")
    raw_parent.mkdir(parents=True, exist_ok=True)
    if raw_parent.is_symlink():
        raise RuntimeError("atomic write parent became a symlink")
    parent = raw_parent.resolve()
    target = parent / requested.name
    if target.is_symlink():
        raise RuntimeError("atomic write target is a symlink and has ambiguous ownership")
    return target


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path = _owned_atomic_target(path)
    rendered = json.dumps(payload, indent=2, sort_keys=True, default=str)
    if len(rendered.encode("utf-8")) > _MAX_RUNTIME_METADATA_BYTES:
        raise ValueError("runtime metadata exceeds persistence size bound")
    fd, raw = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(path)
        fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path = _owned_atomic_target(path)
    fd, raw = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(path)
        fsync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)
