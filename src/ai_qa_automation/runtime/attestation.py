from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..io_safety import read_json_object_bounded, sha256_file_bounded
from ..models import ArtifactRecord, EvidenceItem
from ..state import StateStore
from .journal import RunJournal

_MAX_STATE_BYTES = 16_000_000
_MAX_MANIFEST_BYTES = 16_000_000
_MAX_RUNTIME_BYTES = 2_000_000
_MAX_JOURNAL_BYTES = 64_000_000
_MAX_EVIDENCE_COUNT = 10_000
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

    # Canonical state must have one interpretation everywhere. Reuse StateStore's
    # ambiguity guard and strict JSON-mode schema validation rather than treating
    # attestation as a weaker parallel state reader.
    state = StateStore(state_path).load().model_dump(mode="json")
    runtime = (
        _load_object(runtime_path, max_bytes=_MAX_RUNTIME_BYTES) if runtime_path.is_file() else {}
    )
    manifest = (
        _load_object(manifest_path, max_bytes=_MAX_MANIFEST_BYTES)
        if manifest_path.is_file()
        else {}
    )
    manifest_integrity, evidence_records, artifact_records = _validate_manifest_structure(
        manifest,
        expected_run_id=state["run_id"],
        present=manifest_path.is_file(),
    )

    try:
        if journal_path.is_file() and journal_path.stat().st_size > _MAX_JOURNAL_BYTES:
            journal = {"valid": False, "reason": "journal exceeds attestation size bound"}
        else:
            journal = RunJournal(journal_path, regulated_mode=False).verify()
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
        journal = {"valid": False, "reason": f"{type(exc).__name__}"}

    artifact_integrity = (
        _verify_manifest_artifacts(root, artifact_records)
        if manifest_integrity["valid"]
        else {
            "valid": False,
            "checked": 0,
            "reason": "evidence manifest failed structural validation",
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
    pending_mutation_present = "pending_mutation" in runtime
    pending_mutation = runtime.get("pending_mutation")
    pending_mutation_authority_valid = pending_mutation_present and (
        pending_mutation is None or (isinstance(pending_mutation, dict) and bool(pending_mutation))
    )
    terminal_status = state.get("terminal_status")
    integrity_verified = (
        subjects_complete
        and bool(journal.get("valid"))
        and bool(manifest_integrity.get("valid"))
        and bool(artifact_integrity.get("valid"))
        and pending_mutation_authority_valid
        and pending_mutation is None
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
            "validation_count": len(state.get("validation_results", [])),
            "evidence_count": len(evidence_records),
            "artifact_count": len(artifact_records),
        },
        "integrity": {
            "journal": journal,
            "manifest": manifest_integrity,
            "artifacts": artifact_integrity,
            "pending_mutation": pending_mutation is not None,
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
            "Owned persisted subjects, the journal chain, structurally valid evidence manifest, "
            "and registered artifact hashes passed the available integrity checks. This does not "
            "change the run terminal status or prove environment-dependent capabilities."
            if integrity_verified
            else "One or more persisted run-integrity checks are incomplete or failed."
        ),
    }


def _validate_manifest_structure(
    manifest: dict[str, Any],
    *,
    expected_run_id: str,
    present: bool,
) -> tuple[dict[str, Any], list[EvidenceItem], list[ArtifactRecord]]:
    if not present:
        return (
            {"valid": False, "reason": "evidence-manifest.json is missing"},
            [],
            [],
        )
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or run_id != expected_run_id:
        return ({"valid": False, "reason": "evidence manifest run_id mismatch"}, [], [])
    regulated_mode = manifest.get("regulated_mode")
    if type(regulated_mode) is not bool:
        return (
            {"valid": False, "reason": "evidence manifest regulated_mode must be a boolean"},
            [],
            [],
        )
    raw_evidence = manifest.get("evidence")
    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_evidence, list) or not isinstance(raw_artifacts, list):
        return (
            {"valid": False, "reason": "evidence manifest registries must be lists"},
            [],
            [],
        )
    if len(raw_evidence) > _MAX_EVIDENCE_COUNT:
        return (
            {"valid": False, "reason": "evidence manifest exceeds evidence count limit"},
            [],
            [],
        )
    if len(raw_artifacts) > _MAX_ARTIFACT_COUNT:
        return (
            {"valid": False, "reason": "evidence manifest exceeds artifact count limit"},
            [],
            [],
        )
    try:
        evidence_records = [
            EvidenceItem.model_validate_json(json.dumps(raw), strict=True) for raw in raw_evidence
        ]
        artifact_records = [
            ArtifactRecord.model_validate_json(json.dumps(raw), strict=True)
            for raw in raw_artifacts
        ]
    except (TypeError, ValueError) as exc:
        return (
            {
                "valid": False,
                "reason": f"evidence manifest record schema is invalid: {type(exc).__name__}",
            },
            [],
            [],
        )
    if len({item.id for item in evidence_records}) != len(evidence_records):
        return ({"valid": False, "reason": "evidence manifest has duplicate evidence ids"}, [], [])
    if len({item.artifact_id for item in artifact_records}) != len(artifact_records):
        return ({"valid": False, "reason": "evidence manifest has duplicate artifact ids"}, [], [])
    if len({item.path for item in artifact_records}) != len(artifact_records):
        return (
            {"valid": False, "reason": "evidence manifest has duplicate artifact paths"},
            [],
            [],
        )
    return (
        {
            "valid": True,
            "regulated_mode": regulated_mode,
            "evidence_records": len(evidence_records),
            "artifact_records": len(artifact_records),
        },
        evidence_records,
        artifact_records,
    )


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


def _verify_manifest_artifacts(root: Path, artifacts: list[ArtifactRecord]) -> dict[str, Any]:
    checked = 0
    total_bytes = 0
    for record in artifacts:
        relative_path = record.path
        expected_hash = record.content_hash
        if not expected_hash.startswith("sha256:"):
            return {
                "valid": False,
                "checked": checked,
                "reason": "artifact record lacks a SHA-256 content hash",
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
