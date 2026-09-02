from __future__ import annotations

import hashlib
import json
import os
import tempfile
from _thread import RLock
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..fs_authority import (
    atomic_write_bytes_confined,
    bind_pending_root_authority,
    clear_pending_root_authority,
    descriptor_relative_authority_supported,
    pin_directory_identity,
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
    persistence_root_identity: tuple[int, int] | None = None
    rollback_lineage_before_close: Callable[[PendingMutation], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    rollback_lineage_after_close: Callable[[PendingMutation], None] | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    _lock: RLock = field(default_factory=RLock, init=False, repr=False, compare=False)
    _workspace_identity: tuple[int, int] | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if type(self.circuit_failure_threshold) is not int or self.circuit_failure_threshold < 1:
            raise ValueError("circuit_failure_threshold must be a positive integer")
        if type(self.max_repeated_action) is not int or self.max_repeated_action < 1:
            raise ValueError("max_repeated_action must be a positive integer")
        self.workspace = self.workspace.expanduser().resolve()
        self.metadata_path = self.metadata_path.expanduser()
        metadata_parent = self.metadata_path.parent
        if metadata_parent.is_symlink():
            raise ValueError("runtime persistence directory is a symlink and has ambiguous ownership")
        metadata_parent.mkdir(parents=True, exist_ok=True)
        if descriptor_relative_authority_supported():
            self._workspace_identity = pin_directory_identity(
                self.workspace,
                label="runtime workspace",
            )
            current_persistence_identity = pin_directory_identity(
                metadata_parent,
                label="runtime persistence directory",
            )
            if (
                self.persistence_root_identity is not None
                and current_persistence_identity != self.persistence_root_identity
            ):
                raise ValueError(
                    "runtime persistence directory does not match authorized run persistence root"
                )
            self.persistence_root_identity = current_persistence_identity
        else:
            observed = metadata_parent.stat(follow_symlinks=False)
            current_persistence_identity = (observed.st_dev, observed.st_ino)
            if (
                self.persistence_root_identity is not None
                and current_persistence_identity != self.persistence_root_identity
            ):
                raise ValueError(
                    "runtime persistence directory does not match authorized run persistence root"
                )
            self.persistence_root_identity = current_persistence_identity

    @property
    def workspace_identity(self) -> tuple[int, int] | None:
        """Return the run-lifetime filesystem identity authorized for target mutations."""

        return self._workspace_identity

    def _assert_workspace_identity(self) -> None:
        if self._workspace_identity is None:
            return
        try:
            current = pin_directory_identity(self.workspace, label="runtime workspace")
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError("runtime workspace identity could not be revalidated") from exc
        if current != self._workspace_identity:
            raise RuntimeError("runtime workspace changed identity since authorization")

    def _bind_pending_root_authority(self) -> None:
        bind_pending_root_authority(
            self.workspace,
            self._workspace_identity,
            owner=self.lease_id,
        )

    def _clear_pending_root_authority(self) -> None:
        if not clear_pending_root_authority(
            self.workspace,
            self._workspace_identity,
            owner=self.lease_id,
        ):
            raise RuntimeError("pending workspace root authority is owned by another runtime")

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
                    expected_root_identity=self._workspace_identity,
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
                try:
                    # Existing-file rollback requires a durable run root before its
                    # descriptor-confined backup can be published below that root.
                    self.persist()
                except (OSError, RuntimeError, ValueError) as exc:
                    raise MutationPendingError(
                        f"mutation runtime authority could not be durably prepared: {type(exc).__name__}"
                    ) from exc
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
                        label="mutation rollback directory backup",
                        expected_root_identity=self.persistence_root_identity,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    raise MutationPendingError(
                        f"mutation rollback backup could not be durably prepared: {exc}"
                    ) from exc
                backup_path = run_root / backup_relative

            try:
                self._assert_workspace_identity()
                self._bind_pending_root_authority()
            except RuntimeError as exc:
                if backup_path is not None:
                    self._discard_backup_best_effort(backup_path)
                raise MutationPendingError(str(exc)) from exc

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
                self._clear_pending_root_authority()
                if backup_path is not None:
                    self._discard_backup_best_effort(backup_path)
                raise

    def commit_pending_mutation(self) -> str | None:
        with self._lock:
            pending = self.pending_mutation
            if pending is None:
                return None
            self._assert_workspace_identity()
            backup: Path | None = None
            if pending.existed:
                backup, _ = self._validated_rollback_backup(pending)

            # Clear process-local mutation authority only immediately before the durable
            # pending-state transition. If persistence fails it is rebound before return.
            self._clear_pending_root_authority()
            self.pending_mutation = None
            try:
                self.persist()
            except Exception:
                self.pending_mutation = pending
                try:
                    self._bind_pending_root_authority()
                except RuntimeError as bind_exc:
                    raise RuntimeError(
                        "mutation commit closure failed and pending root authority could not be restored"
                    ) from bind_exc
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
            self._assert_workspace_identity()
            backup: Path | None = None
            rollback_data: bytes | None = None
            if pending.existed:
                backup, rollback_data = self._validated_rollback_backup(pending)

            # Canonical lineage must be durably poisoned before rollback can alter
            # target bytes or clear the runtime transaction. A callback failure leaves
            # both target bytes and pending recovery authority untouched.
            if self.rollback_lineage_before_close is not None:
                self.rollback_lineage_before_close(pending)

            if pending.existed:
                if rollback_data is None:  # pragma: no cover - guarded by backup validation
                    raise RuntimeError("pending rollback bytes are unavailable")
                atomic_write_bytes_confined(
                    self.workspace,
                    pending.relative_path,
                    rollback_data,
                    create_parents=True,
                    create_only=False,
                    label="mutation rollback target",
                    expected_root_identity=self._workspace_identity,
                )
            else:
                try:
                    unlink_file_confined(
                        self.workspace,
                        pending.relative_path,
                        missing_ok=True,
                        label="mutation rollback target",
                        expected_root_identity=self._workspace_identity,
                    )
                except FileNotFoundError:
                    # A prepared new-file mutation may be cancelled before its parent
                    # directory is ever created. The workspace root itself is checked by
                    # descriptor authority; a missing nested parent means no target entry
                    # exists to remove.
                    if not self.workspace.is_dir():
                        raise

            # Rebind pathname identity after the target mutation but before durable
            # transaction closure. A whole-root replacement at this boundary must retain
            # pending/backup authority rather than certifying rollback on another tree.
            self._assert_workspace_identity()

            # Clear process-local mutation authority only immediately before the durable
            # closure. Persistence failure restores both the pending object and binding.
            self._clear_pending_root_authority()
            self.pending_mutation = None
            try:
                self.persist()
            except Exception:
                self.pending_mutation = pending
                try:
                    self._bind_pending_root_authority()
                except RuntimeError as bind_exc:
                    raise RuntimeError(
                        "mutation rollback closure failed and pending root authority could not be restored"
                    ) from bind_exc
                raise

            # Runtime pending authority is now durably closed. Reconcile canonical
            # file accounting before rollback backup disposal or terminal reporting.
            # A callback failure remains fail-closed because the pre-close checkpoint
            # already persisted NOT_VERIFIED lineage.
            if self.rollback_lineage_after_close is not None:
                self.rollback_lineage_after_close(pending)

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
            raise RuntimeError("pending rollback backup escaped rollback directory") from exc
        if len(relative.parts) < 2 or relative.parts[0] != "rollback":
            raise RuntimeError("pending rollback backup escaped rollback directory")

        try:
            data = read_bytes_confined(
                run_root,
                relative,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="pending rollback directory backup",
                expected_root_identity=self.persistence_root_identity,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("pending rollback backup is missing or not a regular file") from exc
        except ValueError as exc:
            message = str(exc)
            if "exceeds" in message and "ingestion limit" in message:
                raise RuntimeError("pending rollback backup exceeds 2 MB safety limit") from exc
            if "symlink" in message:
                raise RuntimeError(message) from exc
            if "changed identity during confined read" in message:
                raise RuntimeError(
                    "pending rollback backup is missing or not a regular file"
                ) from exc
            raise RuntimeError(message) from exc
        except OSError as exc:
            raise RuntimeError("pending rollback backup is unreadable") from exc
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
                label="mutation rollback directory backup cleanup",
                expected_root_identity=self.persistence_root_identity,
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
            atomic_write_json(
                self.metadata_path,
                self.snapshot(include_pending_details=True),
                expected_parent_identity=self.persistence_root_identity,
            )

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
            workspace_root_identity = (
                {
                    "device": self._workspace_identity[0],
                    "inode": self._workspace_identity[1],
                }
                if self._workspace_identity is not None
                else None
            )
            return {
                "lease_id": self.lease_id,
                "workspace": str(self.workspace),
                "workspace_root_identity": workspace_root_identity,
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


def atomic_write_json(
    path: Path,
    payload: dict[str, Any],
    *,
    expected_parent_identity: tuple[int, int] | None = None,
) -> None:
    path = _owned_atomic_target(path)
    rendered_bytes = json.dumps(payload, indent=2, sort_keys=True, default=str).encode("utf-8")
    if len(rendered_bytes) > _MAX_RUNTIME_METADATA_BYTES:
        raise ValueError("runtime metadata exceeds persistence size bound")
    if descriptor_relative_authority_supported():
        current_identity = pin_directory_identity(path.parent, label="runtime metadata directory")
        if expected_parent_identity is not None and current_identity != expected_parent_identity:
            raise RuntimeError("runtime metadata directory changed identity since authorization")
        atomic_write_bytes_confined(
            path.parent,
            path.name,
            rendered_bytes,
            create_parents=False,
            create_only=False,
            label="runtime metadata",
            expected_root_identity=(
                expected_parent_identity if expected_parent_identity is not None else current_identity
            ),
        )
        return
    if expected_parent_identity is not None:
        before = path.parent.stat(follow_symlinks=False)
        if (before.st_dev, before.st_ino) != expected_parent_identity:
            raise RuntimeError("runtime metadata directory changed identity since authorization")
    fd, raw = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(rendered_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        if expected_parent_identity is not None:
            before_replace = path.parent.stat(follow_symlinks=False)
            if (before_replace.st_dev, before_replace.st_ino) != expected_parent_identity:
                raise RuntimeError("runtime metadata directory changed identity since authorization")
        temp.replace(path)
        fsync_directory(path.parent)
        if expected_parent_identity is not None:
            after = path.parent.stat(follow_symlinks=False)
            if (after.st_dev, after.st_ino) != expected_parent_identity:
                raise RuntimeError("runtime metadata directory changed identity during persistence")
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
