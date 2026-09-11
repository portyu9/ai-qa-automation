from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

from ..fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
    read_bytes_confined,
)
from ..io_safety import parse_json_object_strict, read_bytes_bounded, read_json_object_bounded
from ..state import StateStore
from .journal import RunJournal, validate_runtime_journal_binding
from .targeted_execution_observer import normalize_targeted_path
from .validation_truth import RevisionClosure, evaluate_revision_closure

_MAX_RUNTIME_METADATA_BYTES = 2_000_000
_MAX_JOURNAL_BYTES = 64_000_000


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


def _bind_closure_to_canonical_mutation_lineage(
    state_files_modified: list[str],
    *,
    change_revision: int,
    closure: RevisionClosure,
) -> RevisionClosure:
    """Refuse persisted revision closure when canonical modified-file lineage disagrees."""

    if not closure.closed:
        return closure
    if any(normalize_targeted_path(path) != path for path in state_files_modified):
        return RevisionClosure(
            False,
            "canonical_mutation_lineage_mismatch",
            "Persisted modified-file lineage contains a noncanonical repository path.",
            closure.mutation_path,
        )
    if change_revision == 0:
        if not state_files_modified:
            return closure
        return RevisionClosure(
            False,
            "canonical_mutation_lineage_mismatch",
            "Persisted revision zero contains modified-file lineage without a canonical changed revision.",
        )
    mutation_path = closure.mutation_path
    if mutation_path is not None and mutation_path in state_files_modified:
        return closure
    return RevisionClosure(
        False,
        "canonical_mutation_lineage_mismatch",
        "Persisted validation closure mutation subject is absent from canonical modified-file lineage.",
        mutation_path,
    )


def _read_journal_snapshot(
    run_dir: Path,
    journal_path: Path,
    *,
    run_root_identity: tuple[int, int] | None,
) -> bytes:
    """Read one bounded journal subject for exact-snapshot semantic inspection."""

    if run_root_identity is not None:
        return read_bytes_confined(
            run_dir,
            journal_path.name,
            max_bytes=_MAX_JOURNAL_BYTES,
            label="journal.jsonl",
            expected_root_identity=run_root_identity,
        )
    return read_bytes_bounded(
        journal_path,
        max_bytes=_MAX_JOURNAL_BYTES,
        label="journal.jsonl",
    )


def _inspect_verified_journal_mutation_lifecycle(
    raw_journal: bytes,
    *,
    expected_commit: tuple[str, int] | None,
) -> dict[str, object]:
    """Interpret mutation transitions only after RunJournal verified these exact bytes."""

    pending: tuple[str, int | None] | None = None
    expected_commit_count = 0
    prepared_count = 0
    committed_count = 0
    rolled_back_count = 0

    def invalid(code: str) -> dict[str, object]:
        return {
            "valid": False,
            "code": code,
            "expected_commit_count": expected_commit_count,
            "pending_open": pending is not None,
            "prepared_count": prepared_count,
            "committed_count": committed_count,
            "rolled_back_count": rolled_back_count,
        }

    stream = io.BytesIO(raw_journal)
    record_number = 0
    for raw_line in stream:
        if not raw_line.strip():
            continue
        record_number += 1
        try:
            record = parse_json_object_strict(
                raw_line.decode("utf-8"),
                label=f"verified run journal semantic record {record_number}",
            )
        except (UnicodeDecodeError, ValueError):
            return invalid("journal_semantic_parse_failed")
        event = record.get("event")
        if event not in {"mutation_prepared", "mutation_committed", "mutation_rolled_back"}:
            continue
        payload = record.get("payload")
        if not isinstance(payload, dict):
            return invalid("journal_mutation_payload_invalid")
        path = payload.get("path")
        if (
            not isinstance(path, str)
            or not path
            or normalize_targeted_path(path) != path
        ):
            return invalid("journal_mutation_path_invalid")

        if event == "mutation_prepared":
            prepared_count += 1
            if pending is not None:
                return invalid("journal_mutation_prepare_overlap")
            change_revision_before = payload.get("change_revision_before")
            if change_revision_before is not None and (
                type(change_revision_before) is not int or change_revision_before < 0
            ):
                return invalid("journal_mutation_revision_invalid")
            pending = (path, change_revision_before)
            continue

        if pending is None or pending[0] != path:
            return invalid("journal_mutation_transition_without_matching_prepare")
        if event == "mutation_committed":
            committed_count += 1
            if expected_commit is not None and pending == expected_commit:
                expected_commit_count += 1
        else:
            rolled_back_count += 1
        pending = None

    return {
        "valid": True,
        "code": "valid",
        "expected_commit_count": expected_commit_count,
        "pending_open": pending is not None,
        "prepared_count": prepared_count,
        "committed_count": committed_count,
        "rolled_back_count": rolled_back_count,
    }


def _bind_closed_revision_to_journal_mutation_commit(
    closure: RevisionClosure,
    *,
    change_revision: int,
    journal_mutation_lifecycle: dict[str, object],
) -> RevisionClosure:
    """Require exact durable commit semantics before recovery grants changed-revision closure."""

    if not closure.closed or change_revision == 0:
        return closure
    if journal_mutation_lifecycle.get("valid") is not True:
        return RevisionClosure(
            False,
            "journal_mutation_lifecycle_mismatch",
            "Verified journal mutation lifecycle is structurally inconsistent.",
            closure.mutation_path,
        )
    if journal_mutation_lifecycle.get("pending_open") is not False:
        return RevisionClosure(
            False,
            "journal_runtime_pending_mismatch",
            "Verified journal retains an open mutation transaction while runtime authority reports none.",
            closure.mutation_path,
        )
    if journal_mutation_lifecycle.get("expected_commit_count") != 1:
        return RevisionClosure(
            False,
            "journal_mutation_commit_missing",
            "Verified journal does not contain exactly one committed transition for the current changed revision.",
            closure.mutation_path,
        )
    return closure


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

    closure = evaluate_revision_closure(
        state.validation_results,
        current_revision=state.change_revision,
        expected_run_id=state.run_id,
    )
    closure = _bind_closure_to_canonical_mutation_lineage(
        state.files_modified,
        change_revision=state.change_revision,
        closure=closure,
    )
    expected_commit = (
        (closure.mutation_path, state.change_revision - 1)
        if closure.closed and state.change_revision > 0 and closure.mutation_path is not None
        else None
    )

    try:
        before_journal = _read_journal_snapshot(
            run_dir,
            journal_path,
            run_root_identity=run_root_identity,
        )
        before_journal_digest = hashlib.sha256(before_journal).digest()
        del before_journal
        journal_status = RunJournal(
            journal_path,
            regulated_mode=False,
            expected_parent_identity=run_root_identity,
        ).verify()
        verified_journal = _read_journal_snapshot(
            run_dir,
            journal_path,
            run_root_identity=run_root_identity,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        return {
            "recoverable": False,
            "reason": f"journal could not be verified: {type(exc).__name__}",
        }
    if not journal_status["valid"]:
        return {"recoverable": False, "reason": "journal hash chain is invalid"}
    verified_journal_digest = hashlib.sha256(verified_journal).digest()
    if verified_journal_digest != before_journal_digest:
        return {
            "recoverable": False,
            "reason": "journal changed while its recovery snapshot was being verified",
        }
    journal_mutation_lifecycle = _inspect_verified_journal_mutation_lifecycle(
        verified_journal,
        expected_commit=expected_commit,
    )

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

    try:
        final_journal = _read_journal_snapshot(
            run_dir,
            journal_path,
            run_root_identity=run_root_identity,
        )
    except (OSError, RuntimeError, ValueError):
        return {
            "recoverable": False,
            "reason": "journal could not be revalidated after runtime binding",
        }
    if hashlib.sha256(final_journal).digest() != verified_journal_digest:
        return {
            "recoverable": False,
            "reason": "journal changed after runtime authority was read",
        }
    del final_journal
    del verified_journal

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

    if pending_mutation is None:
        closure = _bind_closed_revision_to_journal_mutation_commit(
            closure,
            change_revision=state.change_revision,
            journal_mutation_lifecycle=journal_mutation_lifecycle,
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
        "journal_mutation_lifecycle": journal_mutation_lifecycle,
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
