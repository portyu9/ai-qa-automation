from __future__ import annotations

import hashlib
from pathlib import Path

from ..fs_authority import (
    atomic_write_bytes_confined,
    move_file_noreplace_between_confined_roots,
    read_bytes_confined,
    unlink_file_confined,
)
from .run_control import MutationPendingError, RuntimeControl

_MAX_STRICT_CANDIDATE_BYTES = 2_000_000


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def mutation_publication_original_proof_relative_path(
    relative_path: str,
    candidate_sha256: str,
) -> Path:
    """Return the deterministic run-owned proof path for a publication-time original."""

    if not _valid_sha256(candidate_sha256):
        raise ValueError("candidate sha256 must be 64 lowercase hexadecimal characters")
    path_digest = hashlib.sha256(relative_path.encode("utf-8")).hexdigest()[:24]
    return Path("rollback") / f"{path_digest}.{candidate_sha256}.publication-original.bin"


def _proof_sha256(
    control: RuntimeControl,
    proof_relative: Path,
) -> str:
    data = read_bytes_confined(
        control.metadata_path.parent.expanduser().absolute(),
        proof_relative,
        max_bytes=_MAX_STRICT_CANDIDATE_BYTES,
        label="strict mutation publication original proof",
        expected_root_identity=control.persistence_root_identity,
    )
    return hashlib.sha256(data).hexdigest()


def _restore_claimed_original(
    control: RuntimeControl,
    proof_relative: Path,
    relative_path: str,
) -> None:
    run_root = control.metadata_path.parent.expanduser().absolute()
    try:
        move_file_noreplace_between_confined_roots(
            run_root,
            proof_relative,
            control.workspace,
            relative_path,
            create_destination_parents=False,
            label="strict mutation publication original restoration",
            expected_source_root_identity=control.persistence_root_identity,
            expected_destination_root_identity=control.workspace_identity,
        )
    except FileExistsError as exc:
        raise MutationPendingError(
            "strict mutation publication observed a concurrent target writer; current target and "
            "run-owned original proof were both preserved for manual reconciliation"
        ) from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise MutationPendingError(
            "strict mutation publication could not restore the atomically claimed original safely; "
            "pending authority was retained for manual reconciliation"
        ) from exc


def publish_pending_candidate(
    control: RuntimeControl,
    *,
    relative_path: str,
    expected_original_sha256: str,
    candidate_bytes: bytes,
) -> str:
    """Publish one strict candidate without replacing an unproved pathname entry.

    The current target is first atomically moved into run-owned proof storage with
    RENAME_NOREPLACE. Only an exact evidence-bound original is accepted. The candidate
    is then created at the vacated target with create-only semantics, so a writer that
    races after the claim is preserved rather than overwritten.
    """

    if not _valid_sha256(expected_original_sha256):
        raise ValueError("expected original sha256 must be 64 lowercase hexadecimal characters")
    if not isinstance(candidate_bytes, bytes) or not candidate_bytes:
        raise ValueError("strict mutation candidate bytes must be non-empty bytes")
    if len(candidate_bytes) > _MAX_STRICT_CANDIDATE_BYTES:
        raise ValueError("strict mutation candidate exceeds 2 MB publication safety limit")

    candidate_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    if candidate_sha256 == expected_original_sha256:
        raise MutationPendingError("strict mutation candidate is identical to the original target")

    with control._lock:
        control.assert_mutation_authority_open()
        pending = control.pending_mutation
        if pending is None or not pending.candidate_required:
            raise MutationPendingError(
                "strict candidate publication requires pending strict authority"
            )
        if pending.relative_path != relative_path:
            raise MutationPendingError(
                "strict candidate publication path does not match pending rollback authority"
            )
        if not pending.existed or pending.original_sha256 != expected_original_sha256:
            raise MutationPendingError(
                "strict candidate publication original bytes do not match prepared rollback authority"
            )
        if pending.candidate_sha256 is not None:
            raise MutationPendingError("strict candidate publication authority is already consumed")

        run_root = control.metadata_path.parent.expanduser().absolute()
        proof_relative = mutation_publication_original_proof_relative_path(
            relative_path,
            candidate_sha256,
        )
        try:
            move_file_noreplace_between_confined_roots(
                control.workspace,
                relative_path,
                run_root,
                proof_relative,
                create_destination_parents=False,
                label="strict mutation publication original claim",
                expected_source_root_identity=control.workspace_identity,
                expected_destination_root_identity=control.persistence_root_identity,
            )
        except FileExistsError as exc:
            raise MutationPendingError(
                "strict mutation publication proof path already exists; refusing ambiguous publication"
            ) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            raise MutationPendingError(
                "strict mutation target could not be atomically claimed before publication"
            ) from exc

        try:
            claimed_sha256 = _proof_sha256(control, proof_relative)
        except (OSError, RuntimeError, ValueError) as exc:
            try:
                _restore_claimed_original(control, proof_relative, relative_path)
            except MutationPendingError as restore_exc:
                raise restore_exc from exc
            raise MutationPendingError(
                "strict mutation publication could not verify the claimed original bytes"
            ) from exc

        if claimed_sha256 != expected_original_sha256:
            _restore_claimed_original(control, proof_relative, relative_path)
            raise MutationPendingError(
                "strict mutation target changed after authorization; independently written bytes "
                "were restored and the candidate was not published"
            )

        try:
            control.journal.append(
                "mutation_publication_original_claimed",
                path=relative_path,
                original_sha256=claimed_sha256,
                candidate_sha256=candidate_sha256,
            )
            control.persist()
        except (OSError, RuntimeError, ValueError) as exc:
            try:
                _restore_claimed_original(control, proof_relative, relative_path)
            except MutationPendingError as restore_exc:
                raise restore_exc from exc
            raise RuntimeError(
                "strict mutation publication claim could not be durably journaled"
            ) from exc

        try:
            atomic_write_bytes_confined(
                control.workspace,
                relative_path,
                candidate_bytes,
                create_parents=False,
                create_only=True,
                label="strict mutation candidate publication",
                expected_root_identity=control.workspace_identity,
            )
        except FileExistsError as exc:
            raise MutationPendingError(
                "strict mutation target was concurrently repopulated after original claim; "
                "the writer and run-owned original proof were preserved"
            ) from exc
        except (OSError, RuntimeError, ValueError) as exc:
            try:
                _restore_claimed_original(control, proof_relative, relative_path)
            except MutationPendingError as restore_exc:
                raise restore_exc from exc
            raise MutationPendingError(
                "strict mutation candidate publication failed before candidate ownership binding; "
                "the original target was restored"
            ) from exc

        control.bind_pending_mutation_candidate(relative_path, candidate_sha256)
        try:
            control.journal.append(
                "mutation_candidate_published_noreplace",
                path=relative_path,
                original_sha256=claimed_sha256,
                candidate_sha256=candidate_sha256,
            )
            control.persist()
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError(
                "strict mutation candidate was bound but no-replace publication could not be durably journaled"
            ) from exc

        try:
            unlink_file_confined(
                run_root,
                proof_relative,
                missing_ok=False,
                label="strict mutation publication original proof cleanup",
                expected_root_identity=control.persistence_root_identity,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise MutationPendingError(
                "strict mutation candidate was published and bound but publication proof cleanup "
                "could not be proven; pending authority was retained"
            ) from exc
        return candidate_sha256
