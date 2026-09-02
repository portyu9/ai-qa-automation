from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
)
from ..io_safety import parse_json_object_strict, read_json_object_bounded
from ..state import StateStore
from .journal import RunJournal, validate_runtime_journal_binding
from .validation_truth import evaluate_revision_closure

_MAX_RUNTIME_METADATA_BYTES = 2_000_000


def _validate_workspace_root_authority(
    metadata: dict[str, Any],
    workspace: Path,
) -> dict[str, object]:
    if "workspace_root_identity" not in metadata or metadata["workspace_root_identity"] is None:
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity authority is missing",
        }
    raw = metadata["workspace_root_identity"]
    if not isinstance(raw, dict) or set(raw) != {"device", "inode"}:
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity authority is invalid",
        }
    device = raw.get("device")
    inode = raw.get("inode")
    if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity authority is invalid",
        }
    if not descriptor_relative_authority_supported():
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity cannot be verified on this platform",
        }
    try:
        current = pin_directory_identity(workspace, label="recovery workspace")
    except (OSError, RuntimeError, ValueError):
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity could not be verified",
        }
    if current != (device, inode):
        return {
            "valid": False,
            "reason": "runtime.json workspace root identity does not match current workspace",
        }
    return {"valid": True}


def inspect_recovery(run_dir: Path) -> dict[str, Any]:
    """Assess persisted run integrity without claiming model-session replay."""
    requested_run_dir = run_dir.expanduser()
    if requested_run_dir.is_symlink():
        return {"recoverable": False, "reason": "run directory has ambiguous symlink ownership"}
    run_dir = requested_run_dir.resolve()
    if not run_dir.is_dir():
        return {"recoverable": False, "reason": "run directory is missing"}
    try:
        run_root_identity = (
            pin_directory_identity(run_dir, label="recovery run directory")
            if descriptor_relative_authority_supported()
            else None
        )
    except (OSError, RuntimeError, ValueError):
        return {
            "recoverable": False,
            "reason": "run directory identity could not be verified",
        }
    state_path = run_dir / "state.json"
    journal_path = run_dir / "journal.jsonl"
    runtime_path = run_dir / "runtime.json"
    for path, label in (
        (state_path, "state.json"),
        (journal_path, "journal.jsonl"),
        (runtime_path, "runtime.json"),
    ):
        if path.is_symlink():
            return {"recoverable": False, "reason": f"{label} has ambiguous symlink ownership"}
        if not path.is_file():
            return {"recoverable": False, "reason": f"{label} is missing"}

    try:
        state = StateStore(
            state_path,
            expected_parent_identity=run_root_identity,
        ).load()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"recoverable": False, "reason": f"state could not be loaded: {type(exc).__name__}"}
    try:
        journal_status = RunJournal(
            journal_path,
            regulated_mode=False,
            expected_parent_identity=run_root_identity,
        ).verify()
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        return {
            "recoverable": False,
            "reason": f"journal could not be verified: {type(exc).__name__}",
        }
    if not journal_status["valid"]:
        return {"recoverable": False, "reason": "journal hash chain is invalid"}

    try:
        if run_root_identity is not None:
            raw_runtime = read_bytes_confined(
                run_dir,
                runtime_path.name,
                max_bytes=_MAX_RUNTIME_METADATA_BYTES,
                label="runtime.json",
                expected_root_identity=run_root_identity,
            )
            runtime_metadata = parse_json_object_strict(
                raw_runtime.decode("utf-8"),
                label="runtime.json",
            )
        else:
            runtime_metadata = read_json_object_bounded(
                runtime_path,
                max_bytes=_MAX_RUNTIME_METADATA_BYTES,
                label="runtime.json",
            )
    except UnicodeError:
        return {"recoverable": False, "reason": "runtime.json is not valid UTF-8"}
    except OSError:
        return {"recoverable": False, "reason": "runtime.json is unreadable"}
    except json.JSONDecodeError:
        return {"recoverable": False, "reason": "runtime.json is invalid JSON"}
    except ValueError as exc:
        message = str(exc)
        if "exceeds" in message and "ingestion limit" in message:
            return {"recoverable": False, "reason": "runtime.json exceeds restore size bound"}
        if "root must be a JSON object" in message:
            return {"recoverable": False, "reason": "runtime.json root must be an object"}
        return {
            "recoverable": False,
            "reason": f"runtime.json failed strict object validation: {message}",
        }

    runtime_workspace = runtime_metadata.get("workspace")
    if not isinstance(runtime_workspace, str) or not runtime_workspace:
        return {
            "recoverable": False,
            "reason": "runtime.json workspace identity is invalid",
        }
    canonical_workspace = Path(state.workspace).expanduser().resolve()
    if runtime_workspace != str(canonical_workspace):
        return {
            "recoverable": False,
            "reason": "runtime.json workspace does not match canonical state workspace",
        }
    workspace_authority = _validate_workspace_root_authority(runtime_metadata, canonical_workspace)
    if not workspace_authority["valid"]:
        return {"recoverable": False, "reason": workspace_authority["reason"]}

    journal_binding = validate_runtime_journal_binding(runtime_metadata, journal_status)
    if not journal_binding["valid"]:
        return {
            "recoverable": False,
            "reason": f"runtime journal authority is invalid: {journal_binding['reason']}",
        }

    if "pending_mutation" not in runtime_metadata:
        return {
            "recoverable": False,
            "reason": "runtime.json is missing pending_mutation authority",
        }
    pending_mutation = runtime_metadata["pending_mutation"]
    if pending_mutation is not None and (
        not isinstance(pending_mutation, dict) or not pending_mutation
    ):
        return {
            "recoverable": False,
            "reason": "runtime.json pending_mutation authority is invalid",
        }

    closure = evaluate_revision_closure(
        state.validation_results,
        current_revision=state.change_revision,
    )
    revision_closed = closure.closed
    if pending_mutation is not None:
        revision_closed = False

    return {
        "recoverable": True,
        "run_id": state.run_id,
        "terminal_status": state.terminal_status.value if state.terminal_status else None,
        "change_revision": state.change_revision,
        "revision_closed": revision_closed,
        "revision_closure": {
            "closed": closure.closed,
            "code": closure.code,
            "reason": closure.reason,
            "mutation_path": closure.mutation_path,
        },
        "journal": journal_status,
        "journal_binding": journal_binding,
        "workspace_authority": workspace_authority,
        "runtime": runtime_metadata,
        "pending_mutation": pending_mutation,
        "resume_policy": (
            "safe-to-start-a-new-agent-session-from-persisted-evidence"
            if revision_closed
            else "manual-review-required-before-new-session"
        ),
        "note": "This verifies persisted state; it does not replay or continue a prior model conversation.",
    }
