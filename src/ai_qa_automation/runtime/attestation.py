from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .journal import RunJournal


def build_run_attestation(run_dir: Path) -> dict[str, Any]:
    """Build a content-addressed run-integrity attestation.

    This is deliberately an unsigned integrity statement. It records exactly
    what persisted bytes were inspected and never represents itself as a
    trusted-party signature, SLSA certification, or successful test result.
    """
    root = run_dir.expanduser().resolve()
    state_path = root / "state.json"
    manifest_path = root / "evidence-manifest.json"
    runtime_path = root / "runtime.json"
    journal_path = root / "journal.jsonl"
    if not state_path.is_file():
        raise FileNotFoundError("state.json is required for attestation")

    state = _load_object(state_path)
    runtime = _load_object(runtime_path) if runtime_path.is_file() else {}
    manifest = _load_object(manifest_path) if manifest_path.is_file() else {}

    try:
        journal = RunJournal(journal_path, regulated_mode=False).verify()
    except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        journal = {"valid": False, "reason": f"{type(exc).__name__}"}

    subjects = {
        "state.json": _file_digest(state_path),
        "evidence-manifest.json": _file_digest(manifest_path) if manifest_path.is_file() else None,
        "runtime.json": _file_digest(runtime_path) if runtime_path.is_file() else None,
        "journal.jsonl": _file_digest(journal_path) if journal_path.is_file() else None,
    }
    pending_mutation = runtime.get("pending_mutation") if isinstance(runtime, dict) else None
    terminal_status = state.get("terminal_status")
    integrity_verified = bool(journal.get("valid")) and pending_mutation in (None, {}, False)

    core: dict[str, Any] = {
        "schema": "ai-qa-run-attestation/v1",
        "run_id": state.get("run_id"),
        "objective_hash": _hash_text(str(state.get("objective") or "")),
        "target": {
            "git_sha": state.get("target_git_sha"),
            "workspace_fingerprint": runtime.get("workspace_fingerprint"),
        },
        "runtime": {
            "agent_version": state.get("agent_version"),
            "model_id": state.get("model_id"),
            "sdk_version": state.get("sdk_version"),
            "policy_version": state.get("policy_version"),
            "tool_schema_version": state.get("tool_schema_version"),
            "configuration_version": state.get("configuration_version"),
        },
        "outcome": {
            "terminal_status": terminal_status,
            "terminal_reason": state.get("terminal_reason"),
            "change_revision": state.get("change_revision"),
            "validation_count": len(state.get("validation_results", [])) if isinstance(state.get("validation_results"), list) else 0,
            "evidence_count": len(manifest.get("evidence", [])) if isinstance(manifest.get("evidence"), list) else 0,
            "artifact_count": len(manifest.get("artifacts", [])) if isinstance(manifest.get("artifacts"), list) else 0,
        },
        "integrity": {
            "journal": journal,
            "pending_mutation": bool(pending_mutation),
            "persisted_subjects": subjects,
            "integrity_verified": integrity_verified,
        },
        "signature": {
            "signed": False,
            "reason": "repository provides content-addressed integrity metadata but no trusted signing key",
        },
    }
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return {
        **core,
        "generated_at": datetime.now(UTC).isoformat(),
        "attestation_digest": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "interpretation": (
            "Persisted run records passed the available integrity checks. This does not change "
            "the run terminal status or prove environment-dependent capabilities."
            if integrity_verified
            else "One or more persisted run-integrity checks are incomplete or failed."
        ),
    }


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} root must be an object")
    return value


def _file_digest(path: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {"size": size, "sha256": digest.hexdigest()}


def _hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
