from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .journal import RunJournal
from .run_control import _atomic_write_bytes, atomic_write_json


def recover_stale_mutation(
    *,
    artifact_root: Path,
    workspace: Path,
    previous_lease: dict[str, Any] | None,
    current_workspace_fingerprint: str,
    recovering_run_id: str,
) -> dict[str, Any]:
    """Rollback a crashed mutation only when the worktree still matches its checkpoint."""
    if not previous_lease:
        return {"status": "NONE"}
    previous_run_id = str(previous_lease.get("run_id") or "")
    if not previous_run_id or previous_run_id == recovering_run_id:
        return {"status": "NONE"}
    artifact_root = artifact_root.expanduser().resolve()
    workspace = workspace.expanduser().resolve()
    prior_run_dir = (artifact_root / previous_run_id).resolve()
    try:
        prior_run_dir.relative_to(artifact_root)
    except ValueError:
        return {"status": "BLOCKED", "reason": "prior run directory escaped artifact root"}
    runtime_path = prior_run_dir / "runtime.json"
    if not runtime_path.is_file():
        return {"status": "NONE", "previous_run_id": previous_run_id}
    try:
        metadata = json.loads(runtime_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "BLOCKED", "reason": "prior runtime metadata is unreadable"}
    if str(metadata.get("workspace") or "") != str(workspace):
        return {"status": "BLOCKED", "reason": "prior runtime workspace does not match lease workspace"}
    pending = metadata.get("pending_mutation")
    if not isinstance(pending, dict):
        return {"status": "NONE", "previous_run_id": previous_run_id}
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
    target = (workspace / relative_path).resolve()
    try:
        target.relative_to(workspace)
    except ValueError:
        return {"status": "BLOCKED", "reason": "prior pending mutation path escaped workspace"}

    if bool(pending.get("existed")):
        backup_raw = str(pending.get("backup_path") or "")
        original_sha = str(pending.get("original_sha256") or "")
        if not backup_raw or not original_sha:
            return {"status": "BLOCKED", "reason": "prior rollback backup metadata is incomplete"}
        backup = Path(backup_raw).expanduser().resolve()
        rollback_root = (prior_run_dir / "rollback").resolve()
        try:
            backup.relative_to(rollback_root)
        except ValueError:
            return {"status": "BLOCKED", "reason": "prior rollback backup escaped run rollback directory"}
        try:
            data = backup.read_bytes()
        except OSError:
            return {"status": "BLOCKED", "reason": "prior rollback backup is unavailable"}
        if hashlib.sha256(data).hexdigest() != original_sha:
            return {"status": "BLOCKED", "reason": "prior rollback backup failed integrity verification"}
        _atomic_write_bytes(target, data)
        backup.unlink(missing_ok=True)
    else:
        target.unlink(missing_ok=True)

    metadata["pending_mutation"] = None
    metadata["recovered_by_run_id"] = recovering_run_id
    metadata["recovered_at"] = datetime.now(UTC).isoformat()
    atomic_write_json(runtime_path, metadata)
    try:
        RunJournal(
            prior_run_dir / "journal.jsonl",
            max_events=max(5000, int(metadata.get("journal_event_count", 0)) + 10),
        ).try_append(
            "stale_mutation_recovered",
            recovering_run_id=recovering_run_id,
            path=relative_path,
        )
    except (OSError, RuntimeError, json.JSONDecodeError):
        pass
    return {"status": "RECOVERED", "previous_run_id": previous_run_id, "path": relative_path}
