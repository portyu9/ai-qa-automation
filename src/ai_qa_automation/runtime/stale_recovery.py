from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..io_safety import fsync_directory, read_bytes_bounded, read_text_bounded
from .journal import RunJournal
from .run_control import _atomic_write_bytes, atomic_write_json

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


def _validated_backup_path(rollback_root: Path, backup_raw: str) -> Path:
    raw_rollback_root = rollback_root.expanduser()
    if raw_rollback_root.is_symlink():
        raise ValueError("prior rollback directory is a symlink and has ambiguous ownership")
    rollback_root = raw_rollback_root.resolve()
    raw = Path(backup_raw).expanduser()
    absolute = raw if raw.is_absolute() else rollback_root / raw
    try:
        relative = absolute.absolute().relative_to(rollback_root)
    except ValueError as exc:
        raise ValueError("prior rollback backup escaped run rollback directory") from exc
    if relative == Path() or not relative.parts:
        raise ValueError("prior rollback backup path is invalid")
    return _confined_non_symlink_path(
        rollback_root,
        relative,
        label="prior rollback backup",
    )


def _load_runtime_metadata(runtime_path: Path) -> dict[str, Any]:
    try:
        rendered = read_text_bounded(
            runtime_path,
            max_bytes=_MAX_RUNTIME_METADATA_BYTES,
            label="prior runtime metadata",
        )
        raw = json.loads(rendered)
    except OSError as exc:
        raise ValueError("prior runtime metadata is unreadable") from exc
    except UnicodeError as exc:
        raise ValueError("prior runtime metadata is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("prior runtime metadata is invalid JSON") from exc
    except ValueError as exc:
        raise ValueError("prior runtime metadata exceeds recovery ingestion limit") from exc
    if not isinstance(raw, dict):
        raise ValueError("prior runtime metadata root must be an object")
    return raw


def _validated_journal_event_count(metadata: dict[str, Any]) -> int:
    raw = metadata.get("journal_event_count", 0)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ValueError("prior runtime journal_event_count is invalid")
    if raw < 0 or raw > _MAX_RECOVERY_JOURNAL_EVENTS:
        raise ValueError("prior runtime journal_event_count exceeds recovery safety bounds")
    return int(raw)


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
    previous_run_id = str(previous_lease.get("run_id") or "")
    if not previous_run_id or previous_run_id == recovering_run_id:
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
    if str(metadata.get("workspace") or "") != str(workspace):
        return {
            "status": "BLOCKED",
            "reason": "prior runtime workspace does not match lease workspace",
        }
    pending = metadata.get("pending_mutation")
    if pending in (None, {}, False):
        return {"status": "NONE", "previous_run_id": previous_run_id}
    if not isinstance(pending, dict):
        return {"status": "BLOCKED", "reason": "prior pending mutation metadata is invalid"}
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
    expected_fingerprint = str(metadata.get("workspace_fingerprint") or "")
    if not expected_fingerprint or expected_fingerprint != current_workspace_fingerprint:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "workspace changed after crashed mutation; automatic rollback would risk overwriting newer work",
        }
    relative_path = str(pending.get("relative_path") or "")
    if not relative_path:
        return {"status": "BLOCKED", "reason": "prior pending mutation path is missing"}
    try:
        target = _confined_non_symlink_path(
            workspace,
            Path(relative_path),
            label="prior pending mutation path",
        )
    except ValueError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}

    backup_to_cleanup: Path | None = None
    if bool(pending.get("existed")):
        backup_raw = str(pending.get("backup_path") or "")
        original_sha = str(pending.get("original_sha256") or "")
        if not backup_raw or not original_sha:
            return {"status": "BLOCKED", "reason": "prior rollback backup metadata is incomplete"}
        rollback_root = prior_run_dir / "rollback"
        try:
            backup = _validated_backup_path(rollback_root, backup_raw)
        except ValueError as exc:
            return {"status": "BLOCKED", "reason": str(exc)}
        if not backup.is_file():
            return {"status": "BLOCKED", "reason": "prior rollback backup is unavailable"}
        try:
            data = read_bytes_bounded(
                backup,
                max_bytes=_MAX_ROLLBACK_BYTES,
                label="prior rollback backup",
            )
        except OSError:
            return {"status": "BLOCKED", "reason": "prior rollback backup is unavailable"}
        except ValueError:
            return {
                "status": "BLOCKED",
                "reason": "prior rollback backup exceeds 2 MB recovery safety limit",
            }
        if hashlib.sha256(data).hexdigest() != original_sha:
            return {
                "status": "BLOCKED",
                "reason": "prior rollback backup failed integrity verification",
            }
        _atomic_write_bytes(target, data)
        backup_to_cleanup = backup
    else:
        target.unlink(missing_ok=True)
        fsync_directory(target.parent)

    # The restored target and rollback bytes intentionally coexist until runtime
    # metadata durably closes the pending transaction. If closure fails, preserve
    # the backup and fail closed. The old persisted workspace fingerprint describes
    # the pre-recovery workspace, so a later automatic retry cannot safely assume
    # that a fingerprint mismatch came only from this recovery rather than newer
    # external work; reconciliation must therefore re-establish ownership explicitly.
    metadata["pending_mutation"] = None
    metadata["recovered_by_run_id"] = recovering_run_id
    metadata["recovered_at"] = datetime.now(UTC).isoformat()
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

    rollback_cleanup_failed = False
    if backup_to_cleanup is not None:
        try:
            backup_to_cleanup.unlink()
        except OSError:
            rollback_cleanup_failed = True

    try:
        journal_event_count = _validated_journal_event_count(metadata)
        RunJournal(
            journal_path,
            max_events=min(
                _MAX_RECOVERY_JOURNAL_EVENTS,
                max(5000, journal_event_count + 10),
            ),
        ).try_append(
            "stale_mutation_recovered",
            recovering_run_id=recovering_run_id,
            path=relative_path,
            rollback_cleanup_failed=rollback_cleanup_failed,
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
        # Recovery of target bytes and durable metadata closure have already
        # completed. Journal augmentation is observational and must not resurrect
        # pending state or hide a successful recovery transition.
        pass
    return {"status": "RECOVERED", "previous_run_id": previous_run_id, "path": relative_path}
