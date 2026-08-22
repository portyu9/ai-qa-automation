from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ValidationStatus
from ..state import StateStore
from .journal import RunJournal


def _revision_closed(state: Any) -> bool:
    if state.change_revision == 0:
        return True
    current = [item for item in state.validation_results if item.revision == state.change_revision]
    if not current or any(item.status != ValidationStatus.PASS for item in current):
        return False
    patch_paths = {
        str(item.details.get("path") or "")
        for item in current
        if item.name == "test_patch_safety"
        and item.status == ValidationStatus.PASS
        and str(item.details.get("path") or "")
    }
    if len(patch_paths) != 1:
        return False
    mutation_path = next(iter(patch_paths))
    targeted = any(
        item.name == "pytest"
        and item.status == ValidationStatus.PASS
        and item.details.get("scope") == "targeted"
        and item.details.get("mutation_target_bound") is True
        and item.details.get("mutation_target") == mutation_path
        for item in current
    )
    regression = any(
        item.name == "pytest"
        and item.status == ValidationStatus.PASS
        and item.details.get("scope") == "regression"
        for item in current
    )
    return targeted and regression


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
    if not state_path.is_file():
        return {"recoverable": False, "reason": "state.json is missing"}
    try:
        state = StateStore(state_path).load()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"recoverable": False, "reason": f"state could not be loaded: {type(exc).__name__}"}
    try:
        journal_status = RunJournal(journal_path, regulated_mode=False).verify()
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        return {"recoverable": False, "reason": f"journal could not be verified: {type(exc).__name__}"}
    if not journal_status["valid"]:
        return {"recoverable": False, "reason": "journal hash chain is invalid"}

    revision_closed = _revision_closed(state)
    runtime_metadata: dict[str, Any] = {}
    if runtime_path.is_file():
        try:
            raw_runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"recoverable": False, "reason": "runtime.json is invalid"}
        if isinstance(raw_runtime, dict):
            runtime_metadata = raw_runtime
    pending_mutation = runtime_metadata.get("pending_mutation")
    if pending_mutation:
        revision_closed = False

    return {
        "recoverable": True,
        "run_id": state.run_id,
        "terminal_status": state.terminal_status.value if state.terminal_status else None,
        "change_revision": state.change_revision,
        "revision_closed": revision_closed,
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
