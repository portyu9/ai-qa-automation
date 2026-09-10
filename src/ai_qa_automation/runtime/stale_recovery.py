from __future__ import annotations

import hashlib
import json
from contextlib import suppress
from pathlib import Path
from typing import Any, TypeGuard

from ..fs_authority import (
    atomic_write_bytes_confined,
    descriptor_relative_authority_supported,
    move_file_noreplace_between_confined_roots,
    read_bytes_confined,
    unlink_file_confined,
)
from ..io_safety import parse_json_object_strict, read_json_object_bounded
from . import _stale_recovery_legacy as _legacy
from .journal import RunJournal, validate_runtime_journal_binding
from .run_control import atomic_write_json, mutation_candidate_proof_relative_path


def _is_sha256_hex(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_sha256_fingerprint(value: object) -> TypeGuard[str]:
    return _legacy._is_sha256_fingerprint(value)


def _sha256_or_none(
    root: Path,
    relative_path: str | Path,
    *,
    label: str,
    root_identity: tuple[int, int] | None,
) -> str | None:
    try:
        data = read_bytes_confined(
            root,
            relative_path,
            max_bytes=_legacy._MAX_ROLLBACK_BYTES,
            label=label,
            expected_root_identity=root_identity,
        )
    except FileNotFoundError:
        return None
    return hashlib.sha256(data).hexdigest()


def _restore_misclaimed(
    *,
    prior_run_dir: Path,
    proof_relative: Path,
    workspace: Path,
    relative_path: str,
    run_identity: tuple[int, int] | None,
    workspace_identity: tuple[int, int] | None,
) -> str | None:
    try:
        move_file_noreplace_between_confined_roots(
            prior_run_dir,
            proof_relative,
            workspace,
            relative_path,
            create_destination_parents=False,
            label="stale recovery ownership restoration",
            expected_source_root_identity=run_identity,
            expected_destination_root_identity=workspace_identity,
        )
    except FileExistsError:
        return (
            "stale recovery claimed unexpected bytes and a newer target appeared before "
            "they could be restored; both entries were preserved for manual reconciliation"
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return f"stale recovery could not restore misclaimed target safely: {type(exc).__name__}"
    return None


def _load_runtime_metadata_preserving_missing(
    runtime_path: Path,
    *,
    prior_run_dir: Path,
    expected_run_root_identity: tuple[int, int] | None,
) -> dict[str, Any]:
    """Load prior runtime authority without collapsing an absent file into corruption."""

    try:
        if descriptor_relative_authority_supported():
            raw = read_bytes_confined(
                prior_run_dir,
                runtime_path.name,
                max_bytes=_legacy._MAX_RUNTIME_METADATA_BYTES,
                label="prior runtime metadata",
                expected_root_identity=expected_run_root_identity,
            )
            return parse_json_object_strict(raw.decode("utf-8"), label="prior runtime metadata")
        return read_json_object_bounded(
            runtime_path,
            max_bytes=_legacy._MAX_RUNTIME_METADATA_BYTES,
            label="prior runtime metadata",
        )
    except FileNotFoundError:
        raise
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


def _load_metadata(
    *, artifact_root: Path, workspace: Path, previous_lease: dict[str, Any], recovering_run_id: str
) -> tuple[dict[str, Any], Path, tuple[int, int] | None] | dict[str, Any]:
    raw_previous_run_id = previous_lease.get("run_id")
    if not isinstance(raw_previous_run_id, str) or not raw_previous_run_id.strip():
        return {"status": "BLOCKED", "reason": "prior lease run_id is invalid"}
    if raw_previous_run_id == recovering_run_id:
        return {"status": "NONE"}

    recovery_closed = previous_lease.get("mutation_recovery_closed")
    if "mutation_recovery_closed" in previous_lease and type(recovery_closed) is not bool:
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": "prior lease mutation recovery closure authority is invalid",
        }
    if recovery_closed is True:
        prior_lease_id = previous_lease.get("lease_id")
        if not isinstance(prior_lease_id, str) or not prior_lease_id.strip():
            return {
                "status": "BLOCKED",
                "previous_run_id": raw_previous_run_id,
                "reason": "prior lease mutation recovery closure lacks exact lease identity authority",
            }
        prior_workspace = previous_lease.get("workspace")
        if (
            not isinstance(prior_workspace, str)
            or prior_workspace != str(workspace.expanduser().resolve())
        ):
            return {
                "status": "BLOCKED",
                "previous_run_id": raw_previous_run_id,
                "reason": "prior lease mutation recovery closure is bound to a different workspace",
            }

    artifact_root = artifact_root.expanduser().resolve()
    try:
        prior_run_dir = _legacy._confined_non_symlink_path(
            artifact_root,
            Path(raw_previous_run_id),
            label="prior run directory",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": str(exc),
        }

    try:
        run_identity = _legacy._validated_run_root_identity(previous_lease)
    except ValueError as exc:
        reason = str(exc)
        if recovery_closed is True and "run-root identity authority is missing" in reason:
            reason = "prior lease mutation recovery closure lacks exact run-root identity authority"
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": reason,
        }
    if recovery_closed is True and run_identity is None:
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": "prior lease mutation recovery closure lacks exact run-root identity authority",
        }
    if recovery_closed is True:
        raw_workspace_identity = previous_lease.get("workspace_root_identity")
        if (
            not isinstance(raw_workspace_identity, dict)
            or set(raw_workspace_identity) != {"device", "inode"}
        ):
            return {
                "status": "BLOCKED",
                "previous_run_id": raw_previous_run_id,
                "reason": "prior lease mutation recovery closure lacks exact workspace-root identity authority",
            }
        device = raw_workspace_identity.get("device")
        inode = raw_workspace_identity.get("inode")
        if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
            return {
                "status": "BLOCKED",
                "previous_run_id": raw_previous_run_id,
                "reason": "prior lease mutation recovery closure lacks exact workspace-root identity authority",
            }

    try:
        _legacy._current_run_root_identity(prior_run_dir, run_identity)
        runtime_path = prior_run_dir / "runtime.json"
        metadata = _load_runtime_metadata_preserving_missing(
            runtime_path,
            prior_run_dir=prior_run_dir,
            expected_run_root_identity=run_identity,
        )
    except FileNotFoundError:
        if recovery_closed is True:
            return {"status": "NONE", "previous_run_id": raw_previous_run_id}
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": "prior runtime recovery metadata is unavailable and the prior lease has no durable mutation-recovery closure; manual reconciliation is required",
        }
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "BLOCKED",
            "previous_run_id": raw_previous_run_id,
            "reason": str(exc),
        }
    if metadata.get("workspace") != str(workspace.expanduser().resolve()):
        return {
            "status": "BLOCKED",
            "reason": "prior runtime workspace does not match lease workspace",
        }
    return metadata, prior_run_dir, run_identity


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
    """Recover only exact strict candidates; legacy/unbound mutation metadata is manual-only."""

    if not previous_lease:
        return {"status": "NONE"}
    if (
        not isinstance(recovering_run_id, str)
        or not recovering_run_id.strip()
        or len(recovering_run_id) > _legacy._MAX_RECOVERY_RUN_ID_CHARS
    ):
        return {"status": "BLOCKED", "reason": "recovering run_id is invalid"}
    workspace = workspace.expanduser().resolve()
    loaded = _load_metadata(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=previous_lease,
        recovering_run_id=recovering_run_id,
    )
    if isinstance(loaded, dict):
        return loaded
    metadata, prior_run_dir, run_identity = loaded
    previous_run_id = str(previous_lease["run_id"])

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

    # Run the exact legacy parser/journal/state preflight with a fingerprint that can
    # never equal a valid recovery subject. Its destructive branch is therefore
    # unreachable; any earlier authority failure is returned unchanged.
    sentinel = "__aiqa_strict_recovery_preflight__"
    if metadata.get("workspace_fingerprint") == sentinel:
        sentinel += "2"
    preflight = _legacy.recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint=sentinel,
        recovering_run_id=recovering_run_id,
        current_workspace_fingerprint_complete=current_workspace_fingerprint_complete,
        current_workspace_fingerprint_reasons=current_workspace_fingerprint_reasons,
    )
    expected_preflight_reasons = {
        "workspace changed after crashed mutation; automatic rollback would risk overwriting newer work",
        "workspace changed after a durable stale recovery event; automatic recovery closure would risk accepting newer work",
    }
    if (
        preflight.get("status") != "BLOCKED"
        or preflight.get("reason") not in expected_preflight_reasons
    ):
        return preflight

    relative_path = pending.get("relative_path")
    change_revision_before = pending.get("change_revision_before")
    existed = pending.get("existed")
    if not isinstance(relative_path, str) or not relative_path:
        return {"status": "BLOCKED", "reason": "prior pending mutation path is missing or invalid"}
    if type(change_revision_before) is not int or change_revision_before < 0:
        return {
            "status": "BLOCKED",
            "reason": "prior pending mutation change_revision_before authority is invalid",
        }
    if type(existed) is not bool:
        return {"status": "BLOCKED", "reason": "prior pending mutation existed flag is invalid"}

    candidate_sha = pending.get("candidate_sha256")
    candidate_fingerprint = pending.get("candidate_workspace_fingerprint")
    pre_fingerprint = pending.get("pre_mutation_workspace_fingerprint")
    if (
        pending.get("candidate_required") is not True
        or not _is_sha256_hex(candidate_sha)
        or not _is_sha256_fingerprint(candidate_fingerprint)
        or not _is_sha256_fingerprint(pre_fingerprint)
    ):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "prior pending mutation lacks exact candidate ownership authority; automatic destructive recovery is disabled and manual reconciliation is required",
        }

    prior_lease_id = previous_lease.get("lease_id")
    if (
        not isinstance(prior_lease_id, str)
        or not prior_lease_id
        or metadata.get("lease_id") != prior_lease_id
    ):
        return {
            "status": "BLOCKED",
            "reason": "prior runtime lease identity does not match stale-recovery lease authority",
        }

    try:
        journal_count = _legacy._validated_journal_event_count(metadata)
        journal = RunJournal(
            prior_run_dir / "journal.jsonl",
            max_events=min(_legacy._MAX_RECOVERY_JOURNAL_EVENTS, max(5000, journal_count + 10)),
            expected_parent_identity=run_identity,
        )
        journal_status = journal.verify(include_last_record=True)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        return {
            "status": "BLOCKED",
            "reason": f"prior run journal could not be verified: {type(exc).__name__}",
        }
    binding = validate_runtime_journal_binding(metadata, journal_status)
    recovered_fingerprint: str | None = None
    recovery_event_recorded = False
    if not binding["valid"]:
        resumed = _legacy._resumable_recovery_tail(
            metadata=metadata,
            journal_status=journal_status,
            previous_run_id=previous_run_id,
            relative_path=relative_path,
            change_revision_before=change_revision_before,
        )
        if resumed is None:
            return {
                "status": "BLOCKED",
                "reason": f"prior runtime journal authority is invalid: {binding['reason']}",
            }
        _recovery_actor, recovered_fingerprint = resumed
        recovery_event_recorded = True

    try:
        workspace_identity = _legacy._validated_workspace_root_identity(metadata)
        _legacy._current_workspace_identity(workspace, workspace_identity)
        _legacy._current_run_root_identity(prior_run_dir, run_identity)
    except ValueError as exc:
        return {"status": "BLOCKED", "previous_run_id": previous_run_id, "reason": str(exc)}

    backup_raw = pending.get("backup_path")
    original_sha = pending.get("original_sha256")
    if (
        not existed
        or not isinstance(backup_raw, str)
        or not backup_raw
        or not _is_sha256_hex(original_sha)
    ):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "prior pending mutation lacks exact candidate ownership authority; automatic destructive recovery is disabled and manual reconciliation is required",
        }
    try:
        backup_relative = _legacy._validated_backup_relative(prior_run_dir, backup_raw)
        backup_data = read_bytes_confined(
            prior_run_dir,
            backup_relative,
            max_bytes=_legacy._MAX_ROLLBACK_BYTES,
            label="prior rollback backup",
            expected_root_identity=run_identity,
        )
    except OSError:
        return {"status": "BLOCKED", "reason": "prior rollback backup is unavailable"}
    except (RuntimeError, ValueError) as exc:
        if "exceeds" in str(exc) and "ingestion limit" in str(exc):
            return {
                "status": "BLOCKED",
                "reason": "prior rollback backup exceeds 2 MB recovery safety limit",
            }
        return {"status": "BLOCKED", "reason": str(exc)}
    if hashlib.sha256(backup_data).hexdigest() != original_sha:
        return {
            "status": "BLOCKED",
            "reason": "prior rollback backup failed integrity verification",
        }

    runtime_workspace_fingerprint = metadata.get("workspace_fingerprint")
    if recovery_event_recorded:
        if runtime_workspace_fingerprint not in {candidate_fingerprint, pre_fingerprint}:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "prior runtime workspace authority is not bound to the exact mutation recovery lineage",
            }
    elif runtime_workspace_fingerprint != candidate_fingerprint:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "prior runtime workspace authority is not bound to the exact mutation candidate",
        }

    proof_relative = mutation_candidate_proof_relative_path(relative_path, candidate_sha)
    try:
        proof_sha = _sha256_or_none(
            prior_run_dir,
            proof_relative,
            label="stale mutation candidate proof",
            root_identity=run_identity,
        )
        target_sha = _sha256_or_none(
            workspace,
            relative_path,
            label="stale recovery target",
            root_identity=workspace_identity,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": f"stale candidate ownership could not be observed safely: {type(exc).__name__}",
        }

    if recovery_event_recorded:
        if current_workspace_fingerprint != recovered_fingerprint:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "workspace changed after a durable stale recovery event; automatic recovery closure would risk accepting newer work",
            }
        if proof_sha != candidate_sha:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "durable stale recovery event lost its exact candidate proof; pending authority was retained for manual reconciliation",
            }
        if recovered_fingerprint != pre_fingerprint:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "durable stale recovery event is not bound to the persisted pre-mutation workspace subject",
            }
        if target_sha != original_sha:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "durable stale recovery event does not match the current rollback target bytes; pending authority was retained for manual reconciliation",
            }
    else:
        if proof_sha is None:
            if target_sha == original_sha:
                if current_workspace_fingerprint != pre_fingerprint:
                    return {
                        "status": "BLOCKED",
                        "previous_run_id": previous_run_id,
                        "reason": "stale mutation target is original but the full workspace does not match the persisted pre-mutation subject",
                    }
            else:
                if (
                    current_workspace_fingerprint != candidate_fingerprint
                    or target_sha != candidate_sha
                ):
                    return {
                        "status": "BLOCKED",
                        "previous_run_id": previous_run_id,
                        "reason": "workspace changed after crashed mutation; automatic rollback would risk overwriting newer work",
                    }
                try:
                    move_file_noreplace_between_confined_roots(
                        workspace,
                        relative_path,
                        prior_run_dir,
                        proof_relative,
                        create_destination_parents=False,
                        label="stale recovery candidate claim",
                        expected_source_root_identity=workspace_identity,
                        expected_destination_root_identity=run_identity,
                    )
                    proof_sha = _sha256_or_none(
                        prior_run_dir,
                        proof_relative,
                        label="stale mutation candidate proof",
                        root_identity=run_identity,
                    )
                except FileExistsError:
                    proof_sha = _sha256_or_none(
                        prior_run_dir,
                        proof_relative,
                        label="stale mutation candidate proof",
                        root_identity=run_identity,
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    return {
                        "status": "BLOCKED",
                        "previous_run_id": previous_run_id,
                        "reason": f"stale candidate could not be atomically claimed: {type(exc).__name__}",
                    }
        if proof_sha != candidate_sha:
            try:
                current_after_claim = _sha256_or_none(
                    workspace,
                    relative_path,
                    label="stale recovery target",
                    root_identity=workspace_identity,
                )
            except (OSError, RuntimeError, ValueError):
                current_after_claim = "unreadable"
            if proof_sha is not None and current_after_claim is None:
                restore_error = _restore_misclaimed(
                    prior_run_dir=prior_run_dir,
                    proof_relative=proof_relative,
                    workspace=workspace,
                    relative_path=relative_path,
                    run_identity=run_identity,
                    workspace_identity=workspace_identity,
                )
                if restore_error is not None:
                    return {
                        "status": "BLOCKED",
                        "previous_run_id": previous_run_id,
                        "reason": restore_error,
                    }
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "run-owned stale candidate proof does not match the exact candidate bytes",
            }

        target_sha = _sha256_or_none(
            workspace,
            relative_path,
            label="stale recovery target",
            root_identity=workspace_identity,
        )
        if target_sha is None:
            try:
                atomic_write_bytes_confined(
                    workspace,
                    relative_path,
                    backup_data,
                    create_parents=False,
                    create_only=True,
                    label="stale recovery target",
                    expected_root_identity=workspace_identity,
                )
            except FileExistsError:
                return {
                    "status": "BLOCKED",
                    "previous_run_id": previous_run_id,
                    "reason": "stale rollback target was concurrently repopulated; newer bytes were preserved and pending authority remains open",
                }
            except (OSError, RuntimeError, ValueError) as exc:
                return {
                    "status": "BLOCKED",
                    "previous_run_id": previous_run_id,
                    "reason": f"stale rollback target could not be restored safely: {type(exc).__name__}",
                }
        elif target_sha != original_sha:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "stale rollback target contains newer bytes; refusing to overwrite them",
            }
        if (
            _sha256_or_none(
                workspace,
                relative_path,
                label="stale recovery target",
                root_identity=workspace_identity,
            )
            != original_sha
        ):
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "stale rollback target changed after restoration; pending authority was retained",
            }
        recovered_fingerprint = _legacy._observe_recovered_workspace_fingerprint(
            workspace, expected_workspace_identity=workspace_identity
        )
        if recovered_fingerprint != pre_fingerprint:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "stale mutation target was restored but unrelated workspace state does not match the persisted pre-mutation subject; pending authority was retained",
            }
        try:
            recorded = journal.try_append(
                "stale_mutation_recovered",
                recovering_run_id=recovering_run_id,
                previous_run_id=previous_run_id,
                path=relative_path,
                change_revision_before=change_revision_before,
                runtime_event_count=journal_count,
                runtime_head_hash=metadata.get("journal_head_hash"),
                recovered_workspace_fingerprint=recovered_fingerprint,
            )
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            recorded = False
        if not recorded:
            return {
                "status": "BLOCKED",
                "previous_run_id": previous_run_id,
                "reason": "stale mutation bytes were restored but the recovery journal event could not be durably recorded; rollback authority was retained and manual reconciliation is required",
            }

    # The recovery event proves the workspace is now the exact pre-mutation subject.
    # Rebind that subject in runtime metadata before legacy closure clears pending
    # rollback authority; either journal-proven intermediate stage remains resumable.
    metadata["workspace_fingerprint"] = pre_fingerprint
    try:
        atomic_write_json(
            prior_run_dir / "runtime.json",
            metadata,
            expected_parent_identity=run_identity,
        )
        _legacy._current_run_root_identity(prior_run_dir, run_identity)
    except (OSError, RuntimeError, ValueError):
        return {
            "status": "BLOCKED",
            "previous_run_id": previous_run_id,
            "reason": "stale mutation bytes were restored but recovered workspace authority could not be durably rebound; pending authority was retained for manual reconciliation",
        }

    closure = _legacy.recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease=previous_lease,
        current_workspace_fingerprint=pre_fingerprint,
        recovering_run_id=recovering_run_id,
        current_workspace_fingerprint_complete=current_workspace_fingerprint_complete,
        current_workspace_fingerprint_reasons=current_workspace_fingerprint_reasons,
    )
    if closure.get("status") == "RECOVERED":
        if not recovery_event_recorded:
            closure.pop("resumed_recovery_event", None)
        with suppress(OSError, RuntimeError, ValueError):
            unlink_file_confined(
                prior_run_dir,
                proof_relative,
                missing_ok=True,
                label="stale recovery candidate proof cleanup",
                expected_root_identity=run_identity,
            )
    return closure
