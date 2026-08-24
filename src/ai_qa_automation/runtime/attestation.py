from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..io_safety import read_json_object_bounded, sha256_file_bounded
from .journal import RunJournal

_MAX_STATE_BYTES = 16_000_000
_MAX_MANIFEST_BYTES = 16_000_000
_MAX_RUNTIME_BYTES = 2_000_000
_MAX_JOURNAL_BYTES = 64_000_000
_MAX_ARTIFACT_BYTES = 32_000_000
_MAX_ARTIFACT_COUNT = 5_000
_MAX_TOTAL_ARTIFACT_BYTES = 256_000_000


def build_run_attestation(run_dir: Path) -> dict[str, Any]:
    """Build an unsigned, content-addressed run-integrity attestation.

    Integrity verification covers the owned core persisted subjects, journal
    chain, pending-mutation state, and every artifact registered in the evidence
    manifest. It deliberately does not represent a trusted-party signature,
    compliance certification, or successful test result.
    """
    requested_root = run_dir.expanduser()
    if requested_root.is_symlink():
        raise ValueError("run directory is a symlink and has ambiguous ownership")
    root = requested_root.resolve()
    state_path = _owned_subject(root, "state.json")
    manifest_path = _owned_subject(root, "evidence-manifest.json")
    runtime_path = _owned_subject(root, "runtime.json")
    journal_path = _owned_subject(root, "journal.jsonl")
    if not state_path.is_file():
        raise FileNotFoundError("state.json is required for attestation")

    state = _load_object(state_path, max_bytes=_MAX_STATE_BYTES)
    runtime = (
        _load_object(runtime_path, max_bytes=_MAX_RUNTIME_BYTES) if runtime_path.is_file() else {}
    )
    manifest = (
        _load_object(manifest_path, max_bytes=_MAX_MANIFEST_BYTES)
        if manifest_path.is_file()
        else {}
    )

    try:
        if journal_path.is_file() and journal_path.stat().st_size > _MAX_JOURNAL_BYTES:
            journal = {"valid": False, "reason": "journal exceeds attestation size bound"}
        else:
            journal = RunJournal(journal_path, regulated_mode=False).verify()
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        journal = {"valid": False, "reason": f"{type(exc).__name__}"}

    artifact_integrity = (
        _verify_manifest_artifacts(root, manifest)
        if manifest_path.is_file()
        else {
            "valid": False,
            "checked": 0,
            "reason": "evidence-manifest.json is missing",
        }
    )
    subjects = {
        "state.json": _file_digest(state_path, max_bytes=_MAX_STATE_BYTES),
        "evidence-manifest.json": (
            _file_digest(manifest_path, max_bytes=_MAX_MANIFEST_BYTES)
            if manifest_path.is_file()
            else None
        ),
        "runtime.json": (
            _file_digest(runtime_path, max_bytes=_MAX_RUNTIME_BYTES)
            if runtime_path.is_file()
            else None
        ),
        "journal.jsonl": (
            _file_digest(journal_path, max_bytes=_MAX_JOURNAL_BYTES)
            if journal_path.is_file()
            else None
        ),
    }
    subjects_complete = all(value is not None for value in subjects.values())
    pending_mutation = runtime.get("pending_mutation") if isinstance(runtime, dict) else None
    terminal_status = state.get("terminal_status")
    integrity_verified = (
        subjects_complete
        and bool(journal.get("valid"))
        and bool(artifact_integrity.get("valid"))
        and pending_mutation in (None, {}, False)
    )

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
            "validation_count": (
                len(state.get("validation_results", []))
                if isinstance(state.get("validation_results"), list)
                else 0
            ),
            "evidence_count": (
                len(manifest.get("evidence", []))
                if isinstance(manifest.get("evidence"), list)
                else 0
            ),
            "artifact_count": (
                len(manifest.get("artifacts", []))
                if isinstance(manifest.get("artifacts"), list)
                else 0
            ),
        },
        "integrity": {
            "journal": journal,
            "artifacts": artifact_integrity,
            "pending_mutation": bool(pending_mutation),
            "persisted_subjects": subjects,
            "subjects_complete": subjects_complete,
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
            "Owned persisted subjects, the journal chain, and registered artifact hashes passed "
            "the available integrity checks. This does not change the run terminal status or prove "
            "environment-dependent capabilities."
            if integrity_verified
            else "One or more persisted run-integrity checks are incomplete or failed."
        ),
    }


def _owned_subject(root: Path, name: str) -> Path:
    path = root / name
    if path.is_symlink():
        raise ValueError(f"{name} is a symlink and has ambiguous ownership")
    return path


def _owned_artifact_path(root: Path, relative_path: str) -> Path:
    requested = Path(relative_path)
    if requested.is_absolute() or not requested.parts or ".." in requested.parts:
        raise ValueError("registered artifact path is not a confined relative path")
    cursor = root
    for part in requested.parts:
        if part in {"", "."}:
            continue
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("registered artifact path contains a symlink")
    resolved = (root / requested).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("registered artifact path escapes run directory") from exc
    return resolved


def _verify_manifest_artifacts(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        return {"valid": False, "checked": 0, "reason": "manifest artifacts must be a list"}
    if len(artifacts) > _MAX_ARTIFACT_COUNT:
        return {
            "valid": False,
            "checked": 0,
            "reason": "manifest artifact count exceeds attestation bound",
        }
    checked = 0
    total_bytes = 0
    for raw in artifacts:
        if not isinstance(raw, dict):
            return {"valid": False, "checked": checked, "reason": "artifact record is invalid"}
        relative_path = str(raw.get("path") or "")
        expected_hash = str(raw.get("content_hash") or "")
        if not relative_path or not expected_hash.startswith("sha256:"):
            return {
                "valid": False,
                "checked": checked,
                "reason": "artifact record lacks a path or SHA-256 content hash",
            }
        try:
            path = _owned_artifact_path(root, relative_path)
        except ValueError as exc:
            return {"valid": False, "checked": checked, "reason": str(exc)}
        if not path.is_file():
            return {
                "valid": False,
                "checked": checked,
                "reason": f"registered artifact is missing: {relative_path}",
            }
        try:
            actual_hash, size = sha256_file_bounded(
                path,
                max_bytes=_MAX_ARTIFACT_BYTES,
                label=f"registered artifact {relative_path}",
            )
        except (OSError, ValueError):
            return {
                "valid": False,
                "checked": checked,
                "reason": f"registered artifact exceeds attestation size bound: {relative_path}",
            }
        total_bytes += size
        if total_bytes > _MAX_TOTAL_ARTIFACT_BYTES:
            return {
                "valid": False,
                "checked": checked,
                "reason": "registered artifacts exceed cumulative attestation byte bound",
            }
        if expected_hash != f"sha256:{actual_hash}":
            return {
                "valid": False,
                "checked": checked,
                "reason": f"registered artifact hash mismatch: {relative_path}",
            }
        checked += 1
    return {"valid": True, "checked": checked, "total_bytes": total_bytes}


def _load_object(path: Path, *, max_bytes: int) -> dict[str, Any]:
    return read_json_object_bounded(
        path,
        max_bytes=max_bytes,
        label=f"attestation subject {path.name}",
    )


def _file_digest(path: Path, *, max_bytes: int) -> dict[str, object]:
    digest, size = sha256_file_bounded(
        path,
        max_bytes=max_bytes,
        label=f"attestation subject {path.name}",
    )
    return {"size": size, "sha256": digest}


def _hash_text(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"
