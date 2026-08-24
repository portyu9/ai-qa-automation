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

from ..fs_authority import (
    atomic_write_bytes_confined,
    read_bytes_confined,
    unlink_file_confined,
)
from ..io_safety import fsync_directory
from .budget import BudgetExceededError, ExecutionBudget
from .journal import RunJournal

_MAX_ROLLBACK_BYTES = 2_000_000
_MAX_RUNTIME_METADATA_BYTES = 2_000_000


class CircuitOpenError(RuntimeError):
    """Raised when a repeatedly failing tool circuit has opened."""


class RepeatedActionError(RuntimeError):
    """Raised when one identical authorized request exceeds its bounded repetition budget."""


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
    """Authoritative live operational state for bounded tool execution and mutation recovery."""

    workspace: Path
    budget: ExecutionBudget
    journal: RunJournal
    metadata_path: Path
    lease_id: str
    expected_workspace_fingerprint: str | None = None
    circuit_failure_threshold: int = 3
    max_repeated_action: int = 3
    circuit_failures: dict[str, int] = field(default_factory=dict)
    open_circuits: set[str] = field(default_factory=set)
    repeated_action_counts: dict[str, int] = field(default_factory=dict)
    pending_mutation: PendingMutation | None = None
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.circuit_failure_threshold) is not int or self.circuit_failure_threshold < 1:
            raise ValueError("circuit_failure_threshold must be a positive integer")
        if type(self.max_repeated_action) is not int or self.max_repeated_action < 1:
            raise ValueError("max_repeated_action must be a positive integer")
        self.workspace = self.workspace.expanduser().resolve()
        self.metadata_path = self.metadata_path.expanduser()

    def before_tool(self, tool_name: str) -> None:
        with self._lock:
            if tool_name in self.open_circuits:
                raise CircuitOpenError(f"tool circuit is open after repeated failures: {tool_name}")

    def register_tool_request(self, tool_name: str, input_fingerprint: str) -> None:
        """Apply the one live circuit/repetition rule to an already-charged SDK request."""

        with self._lock:
            if tool_name in self.open_circuits:
                raise CircuitOpenError(f"tool circuit is open after repeated failures: {tool_name}")
            key = f"{tool_name}:{input_fingerprint}"
            seen = self.repeated_action_counts.get(key, 0)
            if seen >= self.max_repeated_action:
                raise RepeatedActionError(
                    f"repeated identical action budget exhausted for tool: {tool_name}"
                )
            self.repeated_action_counts[key] = seen + 1
            self.persist()

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
            self._target(relative_path)

            existed = False
            data: bytes | None = None
            try:
                data = read_bytes_confined(
                    self.workspace,
                    relative_path,
                    max_bytes=_MAX_ROLLBACK_BYTES,
                    label="mutation target",
                )
                existed = True
            except FileNotFoundError:
                existed = False
            except ValueError as exc:
                message = str(exc)
                if "exceeds" in message and "ingestion limit" in message:
                    raise MutationPendingError(
                        "mutation target exceeds 2 MB rollback safety limit"
                    ) from exc
                raise MutationPendingError(message) from exc
            except RuntimeError as exc:
                raise MutationPendingError(str(exc)) from exc

            backup_path: Path | None = None
            original_hash: str | None = None
            if existed:
                if data is None:
                    raise MutationPendingError("mutation rollback bytes are unavailable")
                original_hash = hashlib.sha256(data).hexdigest()
                backup_relative = Path("rollback") / (
                    f"{hashlib.sha256(relative_path.encode()).hexdigest()[:24]}.bin"
                )
                run_root = self.metadata_path.parent.expanduser().absolute()
                try:
                    atomic_write_bytes_confined(
                        run_root,
                        backup_relative,
                        data,
                        create_parents=True,
                        create_only=False,
                        label="mutation rollback backup",
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    raise MutationPendingError(
                        f"mutation rollback backup could not be durably prepared: {type(exc).__name__}"
                    ) from exc
                backup_path = run_root / backup_relative

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
                    self._discard_backup_best_effort(backup_path)
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
                cleanup_failed = not self._discard_backup_best_effort(backup)
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
            self._target(pending.relative_path)
            backup: Path | None = None
            if pending.existed:
                backup, data = self._validated_rollback_backup(pending)
                atomic_write_bytes_confined(
                    self.workspace,
                    pending.relative_path,
                    data,
                    create_parents=True,
                    create_only=False,
                    label="mutation rollback target",
                )
            else:
                try:
                    unlink_file_confined(
                        self.workspace,
                        pending.relative_path,
                        missing_ok=True,
                        label="mutation rollback target",
                    )
                except FileNotFoundError:
                    # A prepared new-file mutation may be cancelled before its parent
                    # directory is ever created. The workspace root itself is checked by
                    # descriptor authority; a missing nested parent means no target entry
                    # exists to remove.
                    if not self.workspace.is_dir():
                        raise

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
                cleanup_failed = not self._discard_backup_best_effort(backup)
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

        run_root = self.metadata_path.parent.expanduser().absolute()
        raw_backup = Path(pending.backup_path).expanduser()
        absolute_backup = raw_backup if raw_backup.is_absolute() else raw_backup.absolute()
        try:
            relative = absolute_backup.relative_to(run_root)
        except ValueError as exc:
            raise RuntimeError("pending rollback backup escaped run directory") from exc
        if len(relative.parts) < 2 or relative.parts[0] != "rollback":
            raise RuntimeError("pending rollback backup escaped rollback directory")

        try:
            data = read_bytes_confined(
                run_root,
                relative,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="pending rollback backup",
            )
        except ValueError as exc:
            message = str(exc)
            if "exceeds" in message and "ingestion limit" in message:
                raise RuntimeError("pending rollback backup exceeds 2 MB safety limit") from exc
            raise RuntimeError(message) from exc
        if hashlib.sha256(data).hexdigest() != pending.original_sha256:
            raise RuntimeError("pending rollback backup failed integrity verification")
        return run_root / relative, data

    def _discard_backup_best_effort(self, backup: Path) -> bool:
        run_root = self.metadata_path.parent.expanduser().absolute()
        try:
            relative = backup.expanduser().absolute().relative_to(run_root)
            if len(relative.parts) < 2 or relative.parts[0] != "rollback":
                return False
            unlink_file_confined(
                run_root,
                relative,
                missing_ok=True,
                label="mutation rollback backup cleanup",
            )
        except (OSError, RuntimeError, ValueError):
            return False
        return True

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
                "max_repeated_action": self.max_repeated_action,
                "repeated_action_counts": dict(sorted(self.repeated_action_counts.items())),
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
