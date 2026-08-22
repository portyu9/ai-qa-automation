from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .budget import BudgetExceededError, ExecutionBudget
from .journal import RunJournal
from .workspace_lease import WorkspaceBusyError, WorkspaceLease


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

    def before_tool(self, tool_name: str) -> None:
        if tool_name in self.open_circuits:
            raise CircuitOpenError(f"tool circuit is open after repeated failures: {tool_name}")

    def record_tool_result(self, tool_name: str, *, failed: bool) -> None:
        if failed:
            failures = self.circuit_failures.get(tool_name, 0) + 1
            self.circuit_failures[tool_name] = failures
            if failures >= self.circuit_failure_threshold:
                self.open_circuits.add(tool_name)
        else:
            self.circuit_failures.pop(tool_name, None)
            self.open_circuits.discard(tool_name)
        self.persist()

    def prepare_mutation(self, relative_path: str) -> None:
        if self.pending_mutation is not None:
            raise MutationPendingError(
                f"a mutation is already pending validation: {self.pending_mutation.relative_path}"
            )
        target = self._target(relative_path)
        rollback_root = self.metadata_path.parent / "rollback"
        rollback_root.mkdir(parents=True, exist_ok=True)
        existed = target.exists()
        backup_path: Path | None = None
        original_hash: str | None = None
        if existed:
            if not target.is_file():
                raise MutationPendingError("mutation target must be a regular file")
            data = target.read_bytes()
            if len(data) > 2_000_000:
                raise MutationPendingError("mutation target exceeds 2 MB rollback safety limit")
            original_hash = hashlib.sha256(data).hexdigest()
            backup_path = rollback_root / (
                f"{hashlib.sha256(relative_path.encode()).hexdigest()[:24]}.bin"
            )
            _atomic_write_bytes(backup_path, data)
        self.pending_mutation = PendingMutation(
            relative_path=relative_path,
            existed=existed,
            backup_path=str(backup_path) if backup_path else None,
            original_sha256=original_hash,
        )
        self.journal.append(
            "mutation_prepared",
            path=relative_path,
            existed=existed,
            original_sha256=original_hash,
        )
        self.persist()

    def commit_pending_mutation(self) -> str | None:
        pending = self.pending_mutation
        if pending is None:
            return None
        if pending.backup_path:
            Path(pending.backup_path).unlink(missing_ok=True)
        self.pending_mutation = None
        self.journal.append("mutation_committed", path=pending.relative_path)
        self.persist()
        return pending.relative_path

    def rollback_pending_mutation(self, *, reason: str) -> str | None:
        pending = self.pending_mutation
        if pending is None:
            return None
        target = self._target(pending.relative_path)
        if pending.existed:
            if not pending.backup_path:
                raise RuntimeError("pending rollback backup is missing")
            backup = Path(pending.backup_path).expanduser().resolve()
            rollback_root = (self.metadata_path.parent / "rollback").resolve()
            try:
                backup.relative_to(rollback_root)
            except ValueError as exc:
                raise RuntimeError("pending rollback backup escaped rollback directory") from exc
            data = backup.read_bytes()
            if hashlib.sha256(data).hexdigest() != pending.original_sha256:
                raise RuntimeError("pending rollback backup failed integrity verification")
            target.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_bytes(target, data)
            backup.unlink(missing_ok=True)
        else:
            target.unlink(missing_ok=True)
        self.pending_mutation = None
        self.journal.append("mutation_rolled_back", path=pending.relative_path, reason=reason)
        self.persist()
        return pending.relative_path

    def set_workspace_fingerprint(self, fingerprint: str) -> None:
        self.expected_workspace_fingerprint = fingerprint
        self.persist()

    def persist(self) -> None:
        atomic_write_json(self.metadata_path, self.snapshot(include_pending_details=True))

    def snapshot(self, *, include_pending_details: bool = False) -> dict[str, Any]:
        pending: object = None
        if self.pending_mutation:
            pending = (
                {
                    "relative_path": self.pending_mutation.relative_path,
                    "existed": self.pending_mutation.existed,
                    "backup_path": self.pending_mutation.backup_path,
                    "original_sha256": self.pending_mutation.original_sha256,
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


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, default=str)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temp = Path(raw)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
