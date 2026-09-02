from __future__ import annotations

import hashlib
import json
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..fs_authority import (
    atomic_write_bytes_confined,
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
    unlink_file_confined,
)
from ..io_safety import parse_json_object_strict, read_json_object_bounded
from ..state import StateStore
from .journal import RunJournal, validate_runtime_journal_binding
from .mutation_lineage import reconcile_rolled_back_mutation
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


def _validated_run_root_identity(previous_lease: dict[str, Any]) -> tuple[int, int] | None:
    """Validate prior lease authority over the run-persistence directory."""

    if "run_root_identity" not in previous_lease:
        if descriptor_relative_authority_supported():
            raise ValueError("prior lease run-root identity authority is missing")
        return None
    raw = previous_lease["run_root_identity"]
    if raw is None:
        if descriptor_relative_authority_supported():
            raise ValueError("prior lease run-root identity authority is missing")
        return None
    if not isinstance(raw, dict) or set(raw) != {"device", "inode"}:
        raise ValueError("prior lease run-root identity authority is invalid")
    device = raw.get("device")
    inode = raw.get("inode")
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        raise ValueError("prior lease run-root identity authority is invalid")
    return device, inode


def _current_run_root_identity(
    prior_run_dir: Path,
    expected: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if expected is None:
        return None
    try:
        current = pin_directory_identity(prior_run_dir, label="prior run persistence directory")
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("prior run persistence directory identity could not be verified") from exc
    if current != expected:
        raise ValueError(
            "prior run persistence directory changed identity after lease publication; automatic recovery is blocked"
        )
    return current


def _load_runtime_metadata(
    runtime_path: Path,
    *,
    prior_run_dir: Path,
    expected_run_root_identity: tuple[int, int] | None,
) -> dict[str, Any]:
    try:
        if descriptor_relative_authority_supported():
            raw = read_bytes_confined(
                prior_run_dir,
                runtime_path.name,
                max_bytes=_MAX_RUNTIME_METADATA_BYTES,
                label="prior runtime metadata",
                expected_root_identity=expected_run_root_identity,
            )
            return parse_json_object_strict(raw.decode("utf-8"), label="prior runtime metadata")
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


def _validated_workspace_root_identity(metadata: dict[str, Any]) -> tuple[int, int] | None:
    """Validate persisted workspace-root authority before automatic rollback."""

    if "workspace_root_identity" not in metadata:
        if descriptor_relative_authority_supported():
            raise ValueError("prior runtime workspace root identity authority is missing")
        return None
    raw = metadata["workspace_root_identity"]
    if raw is None:
        if descriptor_relative_authority_supported():
            raise ValueError("prior runtime workspace root identity authority is missing")
        return None
    if not isinstance(raw, dict) or set(raw) != {"device", "inode"}:
        raise ValueError("prior runtime workspace root identity authority is invalid")
    device = raw.get("device")
    inode = raw.get("inode")
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        raise ValueError("prior runtime workspace root identity authority is invalid")
    return device, inode


def _current_workspace_identity(
    workspace: Path,
    expected: tuple[int, int] | None,
) -> tuple[int, int] | None:
    if expected is None:
        return None
    try:
        current = pin_directory_identity(workspace, label="stale recovery workspace")
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("stale recovery workspace root identity could not be verified") from exc
    if current != expected:
        raise ValueError(
            "workspace root identity changed after crashed mutation; automatic rollback would risk targeting a replacement workspace"
        )
    return current


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
    """Rollback a crashed mutation only when ownership and fingerprint still match."""

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
        expected_run_root_identity = _validated_run_root_identity(previous_lease)
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
        journal_path = _confined_non_symlink_path(
            prior_run_dir,
            Path("journal.jsonl"),
            label="prior run journal",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    runtime_path = prior_run_dir / "runtime.json"
    try:
        if descriptor_relative_authority_supported():
            metadata = _load_runtime_metadata(
                runtime_path,
                prior_run_dir=prior_run_dir,
                expected_run_root_identity=expected_run_root_identity,
            )
        else:
            if runtime_path.is_symlink():
                return {"status": "BLOCKED", "reason": "prior runtime metadata is a symlink"}
            if not runtime_path.is_file():
                return {"status": "NONE", "previous_run_id": previous_run_id}
            metadata = _load_runtime_metadata(
                runtime_path,
                prior_run_dir=prior_run_dir,
                expected_run_root_identity=expected_run_root_identity,
            )
    except FileNotFoundError:
        return {"status": "NONE", "previous_run_id": previous_run_id}
    except ValueError as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    try:
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
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

    try:
        journal_event_count = _validated_journal_event_count(metadata)
        journal = RunJournal(
            journal_path,
            max_events=min(
                _MAX_RECOVERY_JOURNAL_EVENTS,
                max(5000, journal_event_count + 10),
            ),
            expected_parent_identity=expected_run_root_identity,
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

    change_revision_before = pending.get("change_revision_before")
    if type(change_revision_before) is not int or change_revision_before < 0:
        return {
            "status": "BLOCKED",
            "reason": "prior pending mutation change_revision_before authority is invalid",
        }
    state_path = prior_run_dir / "state.json"
    try:
        prior_state_store = StateStore(
            state_path,
            expected_parent_identity=expected_run_root_identity,
        )
        prior_state = prior_state_store.load()
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {
            "status": "BLOCKED",
            "reason": f"prior canonical state could not be verified: {type(exc).__name__}",
        }
    if prior_state.run_id != previous_run_id:
        return {
            "status": "BLOCKED",
            "reason": "prior canonical state run_id does not match lease authority",
        }
    if Path(prior_state.workspace).expanduser().resolve() != workspace:
        return {
            "status": "BLOCKED",
            "reason": "prior canonical state workspace does not match lease workspace",
        }
    if prior_state.change_revision < change_revision_before:
        return {
            "status": "BLOCKED",
            "reason": "prior canonical change revision is behind pending mutation authority",
        }
    if prior_state.change_revision > change_revision_before + 1:
        return {
            "status": "BLOCKED",
            "reason": (
                "prior canonical change revision is more than one revision ahead of pending "
                "mutation authority"
            ),
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

    try:
        expected_workspace_identity = _validated_workspace_root_identity(metadata)
        _current_workspace_identity(workspace, expected_workspace_identity)
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
    except ValueError as exc:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": str(exc),
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
                expected_root_identity=expected_run_root_identity,
            )
            _current_run_root_identity(prior_run_dir, expected_run_root_identity)
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
            _current_run_root_identity(prior_run_dir, expected_run_root_identity)
            atomic_write_bytes_confined(
                workspace,
                relative_path,
                data,
                create_parents=True,
                create_only=False,
                label="stale recovery target",
                expected_root_identity=expected_workspace_identity,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "BLOCKED",
                "reason": f"stale rollback target could not be restored safely: {type(exc).__name__}",
            }
        backup_to_cleanup = backup_relative
    else:
        try:
            _current_run_root_identity(prior_run_dir, expected_run_root_identity)
            unlink_file_confined(
                workspace,
                relative_path,
                missing_ok=True,
                label="stale recovery target",
                expected_root_identity=expected_workspace_identity,
            )
        except FileNotFoundError:
            pass
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "BLOCKED",
                "reason": f"stale rollback target could not be removed safely: {type(exc).__name__}",
            }

    try:
        _current_workspace_identity(workspace, expected_workspace_identity)
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
    except ValueError:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "stale mutation bytes were restored but an authority root changed before recovery "
                "closure; rollback authority was retained and manual reconciliation is required"
            ),
        }

    with suppress(OSError, RuntimeError, ValueError, json.JSONDecodeError):
        journal.try_append(
            "stale_mutation_recovered",
            recovering_run_id=recovering_run_id,
            path=relative_path,
        )
    try:
        post_recovery_journal = journal.verify()
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
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

    reconcile_rolled_back_mutation(
        prior_state,
        relative_path=relative_path,
        change_revision_before=change_revision_before,
    )
    try:
        prior_state_store.save(prior_state)
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
    except (OSError, RuntimeError, ValueError):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": (
                "stale mutation bytes were restored but prior canonical validation lineage could "
                "not be durably reconciled; rollback authority was retained and manual "
                "reconciliation is required"
            ),
        }

    metadata["pending_mutation"] = None
    metadata["recovered_by_run_id"] = recovering_run_id
    metadata["recovered_at"] = datetime.now(UTC).isoformat()
    metadata["journal_event_count"] = post_recovery_journal["events"]
    metadata["journal_head_hash"] = post_recovery_journal["head_hash"]
    try:
        atomic_write_json(
            runtime_path,
            metadata,
            expected_parent_identity=expected_run_root_identity,
        )
        _current_run_root_identity(prior_run_dir, expected_run_root_identity)
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
        with suppress(OSError, RuntimeError, ValueError):
            unlink_file_confined(
                prior_run_dir,
                backup_to_cleanup,
                missing_ok=True,
                label="stale recovery backup cleanup",
                expected_root_identity=expected_run_root_identity,
            )

    return {"status": "RECOVERED", "previous_run_id": previous_run_id, "path": relative_path}
