from __future__ import annotations

import hashlib
import json
import os
import tempfile
from _thread import RLock
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..fs_authority import (
    atomic_noreplace_rename_supported,
    atomic_write_bytes_confined,
    bind_pending_root_authority,
    clear_pending_root_authority,
    descriptor_relative_authority_supported,
    move_file_noreplace_between_confined_roots,
    pin_directory_identity,
    read_bytes_confined,
    stat_confined_entry,
    unlink_file_confined,
)
from ..io_safety import fsync_directory
from .budget import BudgetExceededError, ExecutionBudget
from .journal import RunJournal

_MAX_ROLLBACK_BYTES = 2_000_000
_MAX_RUNTIME_METADATA_BYTES = 2_000_000


def _is_sha256_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def mutation_candidate_proof_relative_path(
    relative_path: str,
    candidate_sha256: str,
) -> Path:
    """Return the run-owned proof path for one exact pending candidate."""

    if (
        len(candidate_sha256) != 64
        or candidate_sha256.lower() != candidate_sha256
        or any(character not in "0123456789abcdef" for character in candidate_sha256)
    ):
        raise ValueError("mutation candidate sha256 must be 64 lowercase hexadecimal characters")
    path_digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:24]
    return Path("rollback") / f"{path_digest}.{candidate_sha256}.candidate.bin"


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
    candidate_required: bool = False
    pre_mutation_workspace_fingerprint: str | None = None
    pre_mutation_context_fingerprint: str | None = None
    candidate_sha256: str | None = None
    candidate_workspace_fingerprint: str | None = None


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
            raise ValueError(
                "runtime persistence directory is a symlink and has ambiguous ownership"
            )
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
        candidate_required: bool = False,
        pre_mutation_context_fingerprint: str | None = None,
    ) -> None:
        with self._lock:
            if not isinstance(candidate_required, bool):
                raise ValueError("candidate_required must be a boolean")
            if candidate_required:
                if not atomic_noreplace_rename_supported():
                    raise MutationPendingError(
                        "strict mutation rollback requires atomic no-replace rename authority"
                    )
                if self._workspace_identity is None or self.persistence_root_identity is None:
                    raise MutationPendingError(
                        "strict mutation rollback requires descriptor-bound workspace and run roots"
                    )
                if not _is_sha256_fingerprint(self.expected_workspace_fingerprint):
                    raise MutationPendingError(
                        "strict mutation rollback requires an exact pre-mutation workspace fingerprint"
                    )
                if not _is_sha256_fingerprint(pre_mutation_context_fingerprint):
                    raise MutationPendingError(
                        "strict mutation rollback requires an exact pre-mutation context fingerprint"
                    )
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

            if candidate_required:
                if not existed:
                    raise MutationPendingError(
                        "strict autonomous mutation currently requires an existing target file"
                    )
                try:
                    target_status = stat_confined_entry(
                        self.workspace,
                        relative_path,
                        label="strict mutation target",
                        expected_root_identity=self._workspace_identity,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    raise MutationPendingError(
                        "strict mutation target filesystem authority could not be verified"
                    ) from exc
                if target_status.st_dev != self.persistence_root_identity[0]:
                    raise MutationPendingError(
                        "strict mutation target and run recovery root must share one filesystem"
                    )

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
                candidate_required=candidate_required,
                pre_mutation_workspace_fingerprint=(
                    self.expected_workspace_fingerprint if candidate_required else None
                ),
                pre_mutation_context_fingerprint=(
                    pre_mutation_context_fingerprint if candidate_required else None
                ),
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
                    candidate_required=candidate_required,
                    pre_mutation_workspace_fingerprint=(
                        self.expected_workspace_fingerprint if candidate_required else None
                    ),
                    pre_mutation_context_fingerprint=(
                        pre_mutation_context_fingerprint if candidate_required else None
                    ),
                )
                # A successful preparation must not return mutation authority until
                # runtime metadata is bound to the exact durable journal head/count.
                self.persist()
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

    @staticmethod
    def _validate_candidate_sha256(candidate_sha256: str) -> None:
        if (
            not isinstance(candidate_sha256, str)
            or len(candidate_sha256) != 64
            or candidate_sha256.lower() != candidate_sha256
            or any(character not in "0123456789abcdef" for character in candidate_sha256)
        ):
            raise ValueError("mutation candidate sha256 must be 64 lowercase hexadecimal characters")

    def _pending_target_sha256(self, pending: PendingMutation) -> str | None:
        try:
            data = read_bytes_confined(
                self.workspace,
                pending.relative_path,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="pending mutation target",
                expected_root_identity=self._workspace_identity,
            )
        except FileNotFoundError:
            return None
        except ValueError as exc:
            message = str(exc)
            if "exceeds" in message and "ingestion limit" in message:
                raise MutationPendingError(
                    "pending mutation target exceeds 2 MB ownership safety limit"
                ) from exc
            raise MutationPendingError(message) from exc
        except (OSError, RuntimeError) as exc:
            raise MutationPendingError("pending mutation target ownership is unreadable") from exc
        return hashlib.sha256(data).hexdigest()

    def bind_pending_mutation_candidate(
        self,
        relative_path: str,
        candidate_sha256: str,
        *,
        candidate_workspace_fingerprint: str | None = None,
    ) -> None:
        """Durably bind a live pending transaction to the exact bytes it produced."""

        with self._lock:
            pending = self.pending_mutation
            if pending is None:
                raise MutationPendingError("no mutation is pending candidate binding")
            self._target(relative_path)
            if relative_path != pending.relative_path:
                raise MutationPendingError(
                    "mutation candidate path does not match pending rollback authority"
                )
            self._validate_candidate_sha256(candidate_sha256)
            if (
                candidate_workspace_fingerprint is not None
                and not _is_sha256_fingerprint(candidate_workspace_fingerprint)
            ):
                raise ValueError(
                    "mutation candidate workspace fingerprint must be sha256:<64 lowercase hex>"
                )
            current_sha256 = self._pending_target_sha256(pending)
            if current_sha256 != candidate_sha256:
                raise MutationPendingError(
                    "mutation candidate bytes changed before ownership could be bound"
                )
            if pending.existed and candidate_sha256 == pending.original_sha256:
                raise MutationPendingError("mutation candidate is identical to the original target")
            if pending.candidate_sha256 is not None:
                if pending.candidate_sha256 != candidate_sha256:
                    raise MutationPendingError("mutation candidate ownership is already bound differently")
                if (
                    candidate_workspace_fingerprint is not None
                    and pending.candidate_workspace_fingerprint
                    not in {None, candidate_workspace_fingerprint}
                ):
                    raise MutationPendingError(
                        "mutation candidate workspace authority is already bound differently"
                    )
                if (
                    pending.candidate_workspace_fingerprint is None
                    and candidate_workspace_fingerprint is not None
                ):
                    pending = replace(
                        pending,
                        candidate_workspace_fingerprint=candidate_workspace_fingerprint,
                    )
                    self.pending_mutation = pending
                    try:
                        self.persist()
                        self.journal.append(
                            "mutation_candidate_workspace_bound",
                            path=relative_path,
                            candidate_sha256=candidate_sha256,
                            candidate_workspace_fingerprint=candidate_workspace_fingerprint,
                        )
                        self.persist()
                    except (BudgetExceededError, OSError, RuntimeError, ValueError) as exc:
                        raise RuntimeError(
                            "mutation candidate workspace binding could not be durably journaled"
                        ) from exc
                return

            bound = replace(
                pending,
                candidate_sha256=candidate_sha256,
                candidate_workspace_fingerprint=candidate_workspace_fingerprint,
            )
            self.pending_mutation = bound
            try:
                # Candidate identity must be durable before validation or rollback can
                # rely on it. If this first publication fails, revert process-local
                # authority to the previously durable pending transaction.
                self.persist()
            except Exception:
                self.pending_mutation = pending
                raise

            try:
                self.journal.append(
                    "mutation_candidate_bound",
                    path=relative_path,
                    candidate_sha256=candidate_sha256,
                    candidate_workspace_fingerprint=candidate_workspace_fingerprint,
                )
                self.persist()
            except (BudgetExceededError, OSError, RuntimeError, ValueError) as exc:
                # Candidate metadata is already durable. Do not erase that ownership
                # proof merely because journal extension/binding became ambiguous.
                raise RuntimeError(
                    "mutation candidate journal persistence could not be guaranteed"
                ) from exc

    def _candidate_proof_relative(self, pending: PendingMutation) -> Path:
        if pending.candidate_sha256 is None:
            raise MutationPendingError("pending live mutation has no bound candidate bytes")
        return mutation_candidate_proof_relative_path(
            pending.relative_path,
            pending.candidate_sha256,
        )

    def _candidate_proof_sha256(self, pending: PendingMutation) -> str | None:
        proof_relative = self._candidate_proof_relative(pending)
        run_root = self.metadata_path.parent.expanduser().absolute()
        try:
            data = read_bytes_confined(
                run_root,
                proof_relative,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="pending mutation candidate proof",
                expected_root_identity=self.persistence_root_identity,
            )
        except FileNotFoundError:
            return None
        except (OSError, RuntimeError, ValueError) as exc:
            raise MutationPendingError(
                "pending mutation candidate proof is unreadable or ambiguous"
            ) from exc
        return hashlib.sha256(data).hexdigest()

    def _restore_misclaimed_target(
        self,
        pending: PendingMutation,
        proof_relative: Path,
    ) -> None:
        run_root = self.metadata_path.parent.expanduser().absolute()
        try:
            move_file_noreplace_between_confined_roots(
                run_root,
                proof_relative,
                self.workspace,
                pending.relative_path,
                create_destination_parents=False,
                label="mutation rollback ownership restoration",
                expected_source_root_identity=self.persistence_root_identity,
                expected_destination_root_identity=self._workspace_identity,
            )
        except FileExistsError as exc:
            raise MutationPendingError(
                "mutation target changed again while ownership was being checked; "
                "claimed and current bytes were both preserved for manual reconciliation"
            ) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise MutationPendingError(
                "mutation target ownership check could not restore non-candidate bytes safely"
            ) from exc

    def _strict_restore_pending_mutation(
        self,
        pending: PendingMutation,
        rollback_data: bytes,
    ) -> Path | None:
        """Restore only an atomically claimed exact framework candidate."""

        if pending.candidate_sha256 is None:
            current_sha256 = self._pending_target_sha256(pending)
            if current_sha256 == pending.original_sha256:
                return None
            raise MutationPendingError(
                "pending live mutation has no bound candidate bytes; refusing destructive rollback"
            )

        proof_relative = self._candidate_proof_relative(pending)
        run_root = self.metadata_path.parent.expanduser().absolute()
        proof_sha256 = self._candidate_proof_sha256(pending)
        current_sha256 = self._pending_target_sha256(pending)

        if proof_sha256 is None and current_sha256 == pending.original_sha256:
            return None

        if proof_sha256 is None:
            if current_sha256 is None:
                raise MutationPendingError(
                    "pending live mutation target disappeared before candidate ownership could be claimed"
                )
            try:
                move_file_noreplace_between_confined_roots(
                    self.workspace,
                    pending.relative_path,
                    run_root,
                    proof_relative,
                    create_destination_parents=False,
                    label="mutation rollback candidate claim",
                    expected_source_root_identity=self._workspace_identity,
                    expected_destination_root_identity=self.persistence_root_identity,
                )
            except FileExistsError:
                proof_sha256 = self._candidate_proof_sha256(pending)
                if proof_sha256 is None:
                    raise MutationPendingError(
                        "mutation candidate proof appeared ambiguously during rollback"
                    ) from None
            except (OSError, RuntimeError, ValueError) as exc:
                raise MutationPendingError(
                    "mutation candidate could not be atomically claimed for rollback"
                ) from exc
            else:
                proof_sha256 = self._candidate_proof_sha256(pending)

        if proof_sha256 != pending.candidate_sha256:
            if proof_sha256 is not None and self._pending_target_sha256(pending) is None:
                self._restore_misclaimed_target(pending, proof_relative)
            raise MutationPendingError(
                "pending live mutation target no longer matches owned candidate bytes; refusing rollback"
            )

        current_sha256 = self._pending_target_sha256(pending)
        if current_sha256 is None:
            try:
                atomic_write_bytes_confined(
                    self.workspace,
                    pending.relative_path,
                    rollback_data,
                    create_parents=False,
                    create_only=True,
                    label="mutation rollback target",
                    expected_root_identity=self._workspace_identity,
                )
            except FileExistsError as exc:
                raise MutationPendingError(
                    "mutation rollback target was concurrently repopulated; newer bytes were preserved"
                ) from exc
            except (OSError, RuntimeError, ValueError) as exc:
                raise MutationPendingError(
                    "mutation rollback target could not be restored without replacement"
                ) from exc
        elif current_sha256 != pending.original_sha256:
            raise MutationPendingError(
                "mutation rollback target contains newer bytes; refusing to overwrite them"
            )

        if self._pending_target_sha256(pending) != pending.original_sha256:
            raise MutationPendingError(
                "mutation rollback target changed after restoration; pending authority was retained"
            )
        return run_root / proof_relative

    def _assert_candidate_owned_for_commit(self, pending: PendingMutation) -> None:
        if not pending.candidate_required:
            return
        if pending.candidate_sha256 is None:
            raise MutationPendingError(
                "pending live mutation has no bound candidate bytes; refusing commit"
            )
        if not _is_sha256_fingerprint(pending.candidate_workspace_fingerprint):
            raise MutationPendingError(
                "pending live mutation has no exact candidate workspace authority; refusing commit"
            )
        if self.expected_workspace_fingerprint != pending.candidate_workspace_fingerprint:
            raise MutationPendingError(
                "runtime workspace authority is not bound to the exact mutation candidate; refusing commit"
            )
        if self._candidate_proof_sha256(pending) is not None:
            raise MutationPendingError(
                "mutation candidate is already in rollback proof state; refusing commit"
            )
        current_sha256 = self._pending_target_sha256(pending)
        if current_sha256 != pending.candidate_sha256:
            raise MutationPendingError(
                "pending live mutation target no longer matches owned candidate bytes; refusing commit"
            )

    def commit_pending_mutation(
        self,
        *,
        current_workspace_fingerprint: str | None = None,
    ) -> str | None:
        with self._lock:
            pending = self.pending_mutation
            if pending is None:
                return None
            self._assert_workspace_identity()
            self._assert_candidate_owned_for_commit(pending)
            if pending.candidate_required:
                if current_workspace_fingerprint != pending.candidate_workspace_fingerprint:
                    raise MutationPendingError(
                        "current workspace does not match the exact candidate subject; refusing commit"
                    )
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

            candidate_proof: Path | None = None
            if pending.candidate_required:
                if rollback_data is None:
                    raise RuntimeError("strict pending rollback bytes are unavailable")
                candidate_proof = self._strict_restore_pending_mutation(pending, rollback_data)
                if not _is_sha256_fingerprint(pending.pre_mutation_workspace_fingerprint):
                    raise MutationPendingError(
                        "strict rollback lost pre-mutation workspace authority; pending state retained"
                    )
                self.expected_workspace_fingerprint = pending.pre_mutation_workspace_fingerprint
            elif pending.existed:
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
                    if not self.workspace.is_dir():
                        raise

            self._assert_workspace_identity()

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

            if self.rollback_lineage_after_close is not None:
                self.rollback_lineage_after_close(pending)

            cleanup_failed = False
            if backup is not None:
                cleanup_failed = not self._discard_backup_best_effort(backup)
            if candidate_proof is not None:
                cleanup_failed = (
                    not self._discard_backup_best_effort(candidate_proof) or cleanup_failed
                )
            self._journal_after_durable_transition(
                "mutation_rolled_back",
                path=pending.relative_path,
                reason=reason,
                rollback_cleanup_failed=cleanup_failed,
            )
            return pending.relative_path

    def _journal_after_durable_transition(self, event: str, **payload: Any) -> None:
        """Bind lifecycle provenance to runtime truth before reporting transition success."""
        try:
            self.journal.append(event, **payload)
        except (BudgetExceededError, OSError, RuntimeError, ValueError) as exc:
            # The transition itself is already durable and must never be undone here.
            # Journal append failures can be ambiguous after fsync, so they cannot be
            # converted into a successful transaction return.
            raise RuntimeError(
                "mutation transition journal persistence could not be guaranteed"
            ) from exc
        try:
            self.persist()
        except (OSError, RuntimeError, ValueError) as exc:
            # A verified journal extension without an exact runtime head/count binding
            # is legitimate infrastructure uncertainty, not a successful transition.
            raise RuntimeError(
                "mutation transition journal binding could not be durably persisted"
            ) from exc

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
        with self._lock, self.journal.authority_binding():
            atomic_write_json(
                self.metadata_path,
                self.snapshot(include_pending_details=True),
                expected_parent_identity=self.persistence_root_identity,
            )

    def snapshot(self, *, include_pending_details: bool = False) -> dict[str, Any]:
        with self._lock, self.journal.authority_binding() as journal_authority:
            pending: object = None
            if self.pending_mutation:
                pending = (
                    {
                        "relative_path": self.pending_mutation.relative_path,
                        "existed": self.pending_mutation.existed,
                        "backup_path": self.pending_mutation.backup_path,
                        "original_sha256": self.pending_mutation.original_sha256,
                        "change_revision_before": self.pending_mutation.change_revision_before,
                        "candidate_required": self.pending_mutation.candidate_required,
                        "pre_mutation_workspace_fingerprint": (
                            self.pending_mutation.pre_mutation_workspace_fingerprint
                        ),
                        "pre_mutation_context_fingerprint": (
                            self.pending_mutation.pre_mutation_context_fingerprint
                        ),
                        "candidate_sha256": self.pending_mutation.candidate_sha256,
                        "candidate_workspace_fingerprint": (
                            self.pending_mutation.candidate_workspace_fingerprint
                        ),
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
                "journal_event_count": journal_authority[0],
                "journal_head_hash": journal_authority[1],
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
                expected_parent_identity
                if expected_parent_identity is not None
                else current_identity
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
                raise RuntimeError(
                    "runtime metadata directory changed identity since authorization"
                )
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
