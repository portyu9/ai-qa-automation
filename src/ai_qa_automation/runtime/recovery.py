from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..io_safety import read_text_bounded
from ..state import StateStore
from .journal import RunJournal
from .validation_truth import evaluate_revision_closure

_MAX_RUNTIME_METADATA_BYTES = 2_000_000


def inspect_recovery(run_dir: Path) -> dict[str, Any]:
    """Assess persisted run integrity without claiming model-session replay."""
    requested_run_dir = run_dir.expanduser()
    if requested_run_dir.is_symlink():
        return {"recoverable": False, "reason": "run directory has ambiguous symlink ownership"}
    run_dir = requested_run_dir.resolve()
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
        state = StateStore(state_path).load()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"recoverable": False, "reason": f"state could not be loaded: {type(exc).__name__}"}
    try:
        journal_status = RunJournal(journal_path, regulated_mode=False).verify()
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        return {
            "recoverable": False,
            "reason": f"journal could not be verified: {type(exc).__name__}",
        }
    if not journal_status["valid"]:
        return {"recoverable": False, "reason": "journal hash chain is invalid"}

    try:
        rendered_runtime = read_text_bounded(
            runtime_path,
            max_bytes=_MAX_RUNTIME_METADATA_BYTES,
            label="runtime.json",
        )
    except UnicodeError:
        return {"recoverable": False, "reason": "runtime.json is not valid UTF-8"}
    except OSError:
        return {"recoverable": False, "reason": "runtime.json is unreadable"}
    except ValueError as exc:
        message = str(exc)
        if "exceeds" in message and "ingestion limit" in message:
            return {"recoverable": False, "reason": "runtime.json exceeds restore size bound"}
        return {
            "recoverable": False,
            "reason": "runtime.json ownership or file-type validation failed",
        }

    try:
        raw_runtime = json.loads(rendered_runtime)
    except json.JSONDecodeError:
        return {"recoverable": False, "reason": "runtime.json is invalid JSON"}
    if not isinstance(raw_runtime, dict):
        return {"recoverable": False, "reason": "runtime.json root must be an object"}
    runtime_metadata: dict[str, Any] = raw_runtime

    closure = evaluate_revision_closure(
        state.validation_results,
        current_revision=state.change_revision,
    )
    revision_closed = closure.closed
    pending_mutation = runtime_metadata.get("pending_mutation")
    if pending_mutation:
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
        "runtime": runtime_metadata,
        "pending_mutation": pending_mutation,
        "resume_policy": (
            "safe-to-start-a-new-agent-session-from-persisted-evidence"
            if revision_closed
            else "manual-review-required-before-new-session"
        ),
        "note": "This verifies persisted state; it does not replay or continue a prior model conversation.",
    }
