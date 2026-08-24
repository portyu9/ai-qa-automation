from __future__ import annotations

import hashlib
import json
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..fs_authority import (
    atomic_write_bytes_confined,
    read_bytes_confined,
    unlink_file_confined,
)
from ..io_safety import read_json_object_bounded
from .journal import RunJournal, validate_runtime_journal_binding
from .run_control import atomic_write_json

_MAX_RUNTIME_METADATA_BYTES = 2_000_000
_MAX_ROLLBACK_BYTES = 2_000_000
_MAX_RECOVERY_JOURNAL_EVENTS = 100_000


def _confined_non_symlink_path(root: Path, requested: Path, *, label: str) -> Path:
    """Resolve an owned path without accepting traversal or symlink aliases."""

    root = root.expanduser().resolve()
    if requested.is_absolute() or not requested.parts or ".." in requested.parts:
        raise ValueError(f"{label} escapes trusted root")
    cursor = root
    for part in requested.parts:
        if part in {"", "."}:
            continue
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"{label} contains a symlink and has ambiguous ownership")
    resolved = (root / requested).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes trusted root") from exc
    return resolved


def _validated_backup_relative(prior_run_dir: Path, backup_raw: str) -> Path:
    """Return the rollback backup as a lexical path below the prior run root."""

    prior_run_dir = prior_run_dir.expanduser().absolute()
    raw = Path(backup_raw).expanduser()
    absolute = raw if raw.is_absolute() else prior_run_dir / "rollback" / raw
    try:
        relative = absolute.absolute().relative_to(prior_run_dir)
    except ValueError as exc:
        raise ValueError("prior rollback backup escaped rollback directory") from exc
    if len(relative.parts) < 2 or relative.parts[0] != "rollback":
        raise ValueError("prior rollback backup escaped run rollback directory")
    return relative


def _load_runtime_metadata(runtime_path: Path) -> dict[str, Any]:
    try:
        return read_json_object_bounded(
            runtime_path,
            max_bytes=_MAX_RUNTIME_METADATA_BYTES,
            label="prior runtime metadata",
        )
    except OSError as exc:
        raise ValueError("prior runtime metadata is unreadable") from exc
    except UnicodeError as exc:
        raise ValueError("prior runtime metadata is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("prior runtime metadata is invalid JSON") from exc
    except ValueError as exc:
        message = str(exc)
        if "exceeds" in message and "ingestion limit" in message:
            raise ValueError("prior runtime metadata exceeds recovery ingestion limit") from exc
        if "root must be a JSON object" in message:
            raise ValueError("prior runtime metadata root must be an object") from exc
        raise ValueError(message) from exc


def _validated_journal_event_count(metadata: dict[str, Any]) -> int:
    if "journal_event_count" not in metadata:
        raise ValueError("prior runtime journal_event_count authority is missing")
    raw = metadata["journal_event_count"]
    if type(raw) is not int:
        raise ValueError("prior runtime journal_event_count is invalid")
    if raw < 0 or raw > _MAX_RECOVERY_JOURNAL_EVENTS:
        raise ValueError("prior runtime journal_event_count exceeds recovery safety bounds")
    return raw


def recover_stale_mutation(
    *,
    artifact_root: Path,
    workspace: Path,
    previous_lease: dict[str, Any] | None,
    current_workspace_fingerprint: str,
    recovering_run_id: str,
    current_workspace_fingerprint_complete: bool = True,
    current_workspace_fingerprint_reasons: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Rollback a crashed mutation only when ownership and fingerprint still match.

    Fingerprint completeness is relevant only after a real pending transaction is
    discovered. A normal prior lease record with no pending mutation must not block
    a new run merely because its current worktree is too complex to authorize an
    autonomous write.
    """
    if not previous_lease:
        return {"status": "NONE"}
    raw_previous_run_id = previous_lease.get("run_id")
    if not isinstance(raw_previous_run_id, str) or not raw_previous_run_id.strip():
        return {"status": "BLOCKED", "reason": "prior lease run_id is invalid"}
    previous_run_id = raw_previous_run_id
    if previous_run_id == recovering_run_id:
        return {"status": "NONE"}
    artifact_root = artifact_root.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    try:
        prior_run_dir = _confined_non_symlink_path(
            artifact_root,
            Path(previous_run_id),
            label="prior run directory",
        )
        journal_path = _confined_non_symlink_path(
            prior_run_dir,
            Path("journal.jsonl"),
            label="prior run journal",
        )
    except ValueError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    runtime_path = prior_run_dir / "runtime.json"
    if runtime_path.is_symlink():
        return {"status": "BLOCKED", "reason": "prior runtime metadata is a symlink"}
    if not runtime_path.is_file():
        return {"status": "NONE", "previous_run_id": previous_run_id}
    try:
        metadata = _load_runtime_metadata(runtime_path)
    except ValueError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    metadata_workspace = metadata.get("workspace")
    if not isinstance(metadata_workspace, str) or metadata_workspace != str(workspace):
        return {
            "status": "BLOCKED",
            "reason": "prior runtime workspace does not match lease workspace",
        }
    if "pending_mutation" not in metadata:
        return {
            "status": "BLOCKED",
            "reason": "prior runtime metadata is missing pending_mutation authority",
        }
    pending = metadata["pending_mutation"]
    if pending is None:
        return {"status": "NONE", "previous_run_id": previous_run_id}
    if not isinstance(pending, dict) or not pending:
        return {"status": "BLOCKED", "reason": "prior pending mutation metadata is invalid"}

    # A real pending mutation is authority-bearing and may trigger a workspace write.
    # Bind the journal to the exact count/head captured in runtime.json before any
    # fingerprint/path/rollback action can touch the target workspace.
    try:
        journal_event_count = _validated_journal_event_count(metadata)
        journal = RunJournal(
            journal_path,
            max_events=min(
                _MAX_RECOVERY_JOURNAL_EVENTS,
                max(5000, journal_event_count + 10),
            ),
        )
        journal_status = journal.verify()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "status": "BLOCKED",
            "reason": f"prior run journal could not be verified: {type(exc).__name__}",
        }
    journal_binding = validate_runtime_journal_binding(metadata, journal_status)
    if not journal_binding["valid"]:
        return {
            "status": "BLOCKED",
            "reason": f"prior runtime journal authority is invalid: {journal_binding['reason']}",
        }

    if not current_workspace_fingerprint_complete:
        reasons = ", ".join(current_workspace_fingerprint_reasons) or "unspecified"
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "workspace fingerprint is incomplete; automatic stale rollback cannot prove "
                f"ownership of every changed subject ({reasons})"
            ),
        }
    expected_fingerprint = metadata.get("workspace_fingerprint")
    if (
        not isinstance(expected_fingerprint, str)
        or not expected_fingerprint
        or expected_fingerprint != current_workspace_fingerprint
    ):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "workspace changed after crashed mutation; automatic rollback would risk overwriting newer work",
        }
    relative_path = pending.get("relative_path")
    if not isinstance(relative_path, str) or not relative_path:
        return {"status": "BLOCKED", "reason": "prior pending mutation path is missing or invalid"}
    existed = pending.get("existed")
    if type(existed) is not bool:
        return {"status": "BLOCKED", "reason": "prior pending mutation existed flag is invalid"}
    try:
        _confined_non_symlink_path(
            workspace,
            Path(relative_path),
            label="prior pending mutation path",
        )
    except ValueError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}

    backup_to_cleanup: Path | None = None
    if existed:
        backup_raw = pending.get("backup_path")
        original_sha = pending.get("original_sha256")
        if (
            not isinstance(backup_raw, str)
            or not backup_raw
            or not isinstance(original_sha, str)
            or not original_sha
        ):
            return {"status": "BLOCKED", "reason": "prior rollback backup metadata is incomplete"}
        try:
            backup_relative = _validated_backup_relative(prior_run_dir, backup_raw)
            data = read_bytes_confined(
                prior_run_dir,
                backup_relative,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="prior rollback backup",
            )
        except OSError:
            return {"status": "BLOCKED", "reason": "prior rollback backup is unavailable"}
        except RuntimeError as exc:
            return {
                "status": "BLOCKED",
                "reason": f"prior rollback backup authority is unavailable: {type(exc).__name__}",
            }
        except ValueError as exc:
            if "exceeds" in str(exc) and "ingestion limit" in str(exc):
                return {
                    "status": "BLOCKED",
                    "reason": "prior rollback backup exceeds 2 MB recovery safety limit",
                }
            return {"status": "BLOCKED", "reason": str(exc)}
        if hashlib.sha256(data).hexdigest() != original_sha:
            return {
                "status": "BLOCKED",
                "reason": "prior rollback backup failed integrity verification",
            }
        try:
            atomic_write_bytes_confined(
                workspace,
                relative_path,
                data,
                create_parents=True,
                create_only=False,
                label="stale recovery target",
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "BLOCKED",
                "reason": f"stale rollback target could not be restored safely: {type(exc).__name__}",
            }
        backup_to_cleanup = backup_relative
    else:
        try:
            unlink_file_confined(
                workspace,
                relative_path,
                missing_ok=True,
                label="stale recovery target",
            )
        except FileNotFoundError:
            # The failed mutation may never have created a missing nested parent.
            # A missing parent therefore means there is no target entry to remove.
            pass
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "BLOCKED",
                "reason": f"stale rollback target could not be removed safely: {type(exc).__name__}",
            }

    # Recovery journal augmentation remains observational: inability to append the
    # event does not undo already-restored target bytes. But runtime closure must be
    # bound to the journal state that actually exists after the attempt. If the
    # journal becomes unverifiable, preserve pending authority and require manual
    # reconciliation rather than certifying a clean recovery transition.
    with suppress(OSError, RuntimeError, ValueError, json.JSONDecodeError):
        journal.try_append(
            "stale_mutation_recovered",
            recovering_run_id=recovering_run_id,
            path=relative_path,
        )
    try:
        post_recovery_journal = journal.verify()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "stale mutation bytes were restored but prior journal authority became unreadable; "
                "rollback authority was retained and manual reconciliation is required"
            ),
        }
    if not post_recovery_journal["valid"]:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "stale mutation bytes were restored but prior journal authority became invalid; "
                "rollback authority was retained and manual reconciliation is required"
            ),
        }

    # The restored target and rollback bytes intentionally coexist until runtime
    # metadata durably closes the pending transaction. If closure fails, preserve
    # the backup and fail closed. The persisted journal count/head are updated in
    # the same runtime transition so future inspection cannot accept a valid but
    # different journal chain as the prior run's authority.
    metadata["pending_mutation"] = None
    metadata["recovered_by_run_id"] = recovering_run_id
    metadata["recovered_at"] = datetime.now(UTC).isoformat()
    metadata["journal_event_count"] = post_recovery_journal["events"]
    metadata["journal_head_hash"] = post_recovery_journal["head_hash"]
    try:
        atomic_write_json(runtime_path, metadata)
    except (OSError, RuntimeError, ValueError):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "stale mutation bytes were restored but recovery metadata could not be "
                "durably closed; rollback authority was retained and manual reconciliation "
                "is required before another automatic recovery attempt"
            ),
        }

    if backup_to_cleanup is not None:
        # Runtime authority is already durably closed. An orphaned rollback
        # snapshot is safer than weakening the completed recovery transition.
        with suppress(OSError, RuntimeError, ValueError):
            unlink_file_confined(
                prior_run_dir,
                backup_to_cleanup,
                missing_ok=True,
                label="stale recovery backup cleanup",
            )

    return {"status": "RECOVERED", "previous_run_id": previous_run_id, "path": relative_path}
