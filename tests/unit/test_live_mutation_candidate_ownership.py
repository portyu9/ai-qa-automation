from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ai_qa_automation.fs_authority as fs_authority_module
import ai_qa_automation.runtime.live_services as live_services_module
import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.fs_authority import move_file_noreplace_between_confined_roots
from ai_qa_automation.models import AgentRunState, EvidenceItem, EvidenceKind, EvidenceNature
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import (
    MutationPendingError,
    RuntimeControl,
    mutation_candidate_proof_relative_path,
)
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)
from ai_qa_automation.state import StateStore

_PRE_WORKSPACE_FINGERPRINT = "sha256:" + "1" * 64
_PRE_CONTEXT_FINGERPRINT = "sha256:" + "2" * 64
_CANDIDATE_WORKSPACE_FINGERPRINT = "sha256:" + "3" * 64


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-live-mutation-candidate-ownership",
        expected_workspace_fingerprint=_PRE_WORKSPACE_FINGERPRINT,
    )


def _existing_target(subject: RuntimeControl) -> tuple[str, Path, bytes]:
    relative = "tests/test_target.py"
    target = subject.workspace / relative
    target.parent.mkdir(parents=True)
    original = b"def test_target():\n    assert True\n"
    target.write_bytes(original)
    return relative, target, original


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prepare_strict(subject: RuntimeControl, relative: str) -> None:
    subject.prepare_mutation(
        relative,
        change_revision_before=0,
        candidate_required=True,
        pre_mutation_context_fingerprint=_PRE_CONTEXT_FINGERPRINT,
    )


def _bind_strict(
    subject: RuntimeControl,
    relative: str,
    target: Path,
    candidate: bytes,
) -> None:
    target.write_bytes(candidate)
    subject.bind_pending_mutation_candidate(
        relative,
        _sha256(candidate),
        candidate_workspace_fingerprint=_CANDIDATE_WORKSPACE_FINGERPRINT,
    )
    subject.set_workspace_fingerprint(_CANDIDATE_WORKSPACE_FINGERPRINT)


def test_strict_rollback_preserves_newer_independent_writer_bytes(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 1 == 1\n"
    independent = b"def test_target():\n    assert 'newer independent work'\n"

    _prepare_strict(subject, relative)
    _bind_strict(subject, relative, target, candidate)
    target.write_bytes(independent)

    with pytest.raises(MutationPendingError, match="no longer matches owned candidate bytes"):
        subject.rollback_pending_mutation(reason="later validation failed")

    assert target.read_bytes() == independent
    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 == _sha256(candidate)
    assert subject.pending_mutation.backup_path is not None
    assert Path(subject.pending_mutation.backup_path).is_file()


def test_strict_commit_preserves_pending_authority_after_candidate_drift(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 2 == 2\n"
    independent = b"def test_target():\n    assert 'external writer'\n"

    _prepare_strict(subject, relative)
    _bind_strict(subject, relative, target, candidate)
    target.write_bytes(independent)

    with pytest.raises(MutationPendingError, match="no longer matches owned candidate bytes"):
        subject.commit_pending_mutation(
            current_workspace_fingerprint=_CANDIDATE_WORKSPACE_FINGERPRINT
        )

    assert target.read_bytes() == independent
    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 == _sha256(candidate)


def test_strict_commit_requires_exact_candidate_workspace_subject(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 2 + 2 == 4\n"

    _prepare_strict(subject, relative)
    _bind_strict(subject, relative, target, candidate)

    with pytest.raises(MutationPendingError, match="current workspace"):
        subject.commit_pending_mutation(
            current_workspace_fingerprint="sha256:" + "9" * 64
        )

    assert subject.pending_mutation is not None
    assert (
        subject.commit_pending_mutation(
            current_workspace_fingerprint=_CANDIDATE_WORKSPACE_FINGERPRINT
        )
        == relative
    )
    assert subject.pending_mutation is None
    assert subject.expected_workspace_fingerprint == _CANDIDATE_WORKSPACE_FINGERPRINT


def test_strict_rollback_restores_exact_owned_candidate(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 3 == 3\n"

    _prepare_strict(subject, relative)
    _bind_strict(subject, relative, target, candidate)

    assert subject.rollback_pending_mutation(reason="semantic validation failed") == relative
    assert target.read_bytes() == original
    assert subject.pending_mutation is None
    assert subject.expected_workspace_fingerprint == _PRE_WORKSPACE_FINGERPRINT


def test_strict_rollback_closes_safely_when_existing_target_never_changed(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, original = _existing_target(subject)

    _prepare_strict(subject, relative)

    assert subject.rollback_pending_mutation(reason="tool failed before write") == relative
    assert target.read_bytes() == original
    assert subject.pending_mutation is None


def test_strict_prepare_rejects_originally_absent_target(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative = "tests/test_new.py"
    target = subject.workspace / relative

    with pytest.raises(MutationPendingError, match="requires an existing target file"):
        _prepare_strict(subject, relative)

    assert not target.exists()
    assert subject.pending_mutation is None


def test_strict_unbound_changed_target_refuses_destructive_rollback(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    unbound = b"def test_target():\n    assert 'write before ownership bind'\n"

    _prepare_strict(subject, relative)
    target.write_bytes(unbound)

    with pytest.raises(MutationPendingError, match="no bound candidate bytes"):
        subject.rollback_pending_mutation(reason="tool failed after write")

    assert target.read_bytes() == unbound
    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 is None


def test_candidate_binding_requires_current_exact_digest(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 4 == 4\n"

    _prepare_strict(subject, relative)
    target.write_bytes(candidate)

    with pytest.raises(MutationPendingError, match="changed before ownership could be bound"):
        subject.bind_pending_mutation_candidate(relative, "0" * 64)

    assert target.read_bytes() == candidate
    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 is None


def test_candidate_binding_rejects_non_string_digest_deterministically(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 5 == 5\n"

    _prepare_strict(subject, relative)
    target.write_bytes(candidate)

    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        subject.bind_pending_mutation_candidate(relative, cast(Any, 123))

    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 is None


def test_writer_after_candidate_claim_is_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"candidate\n"
    newer = b"newer writer\n"

    _prepare_strict(subject, relative)
    _bind_strict(subject, relative, target, candidate)
    real_move = move_file_noreplace_between_confined_roots
    calls = 0

    def racing_move(*args: object, **kwargs: object) -> tuple[int, int]:
        nonlocal calls
        result = real_move(*args, **kwargs)
        calls += 1
        if calls == 1:
            target.write_bytes(newer)
        return result

    monkeypatch.setattr(
        run_control_module,
        "move_file_noreplace_between_confined_roots",
        racing_move,
    )

    with pytest.raises(MutationPendingError, match="newer bytes"):
        subject.rollback_pending_mutation(reason="later validation failed")

    assert target.read_bytes() == newer
    pending = subject.pending_mutation
    assert pending is not None and pending.candidate_sha256 == _sha256(candidate)
    proof = subject.metadata_path.parent / mutation_candidate_proof_relative_path(
        relative,
        _sha256(candidate),
    )
    assert proof.read_bytes() == candidate


def test_atomic_claim_restores_source_swapped_before_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "workspace"
    destination_root = tmp_path / "run"
    source_root.mkdir()
    (destination_root / "rollback").mkdir(parents=True)
    source = source_root / "candidate.py"
    destination = destination_root / "rollback" / "candidate.bin"
    saved_candidate = source_root / "candidate.py.concurrent-saved"
    candidate = b"framework candidate\n"
    newer = b"newer independent writer\n"
    source.write_bytes(candidate)

    real_rename = fs_authority_module._renameat2_noreplace
    swapped = False

    def swap_before_rename(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            os.rename(
                source_name,
                saved_candidate.name,
                src_dir_fd=source_parent_fd,
                dst_dir_fd=source_parent_fd,
            )
            writer_fd = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=source_parent_fd,
            )
            try:
                os.write(writer_fd, newer)
                os.fsync(writer_fd)
            finally:
                os.close(writer_fd)
        real_rename(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )

    monkeypatch.setattr(fs_authority_module, "_renameat2_noreplace", swap_before_rename)

    with pytest.raises(ValueError, match="source changed before atomic claim"):
        move_file_noreplace_between_confined_roots(
            source_root,
            source.name,
            destination_root,
            Path("rollback") / destination.name,
            create_destination_parents=False,
            label="test candidate claim",
        )

    assert source.read_bytes() == newer
    assert saved_candidate.read_bytes() == candidate
    assert not destination.exists()


def test_live_locator_prepare_uses_evidence_resolved_subject_without_raw_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _control(tmp_path)
    relative, target, original = _existing_target(subject)
    state = AgentRunState(
        objective="prepare locator mutation from evidence subject",
        workspace=str(subject.workspace),
        target_git_sha="a" * 40,
    )
    store = StateStore(subject.metadata_path.parent / "state.json")
    store.save(state)
    services = LiveRuntimeServices(
        workspace=subject.workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=PolicyEngine(
            tmp_path / "control",
            subject.workspace,
            allow_test_writes=True,
        ),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=subject.workspace_identity,
        control=subject,
    )
    monkeypatch.setattr(
        live_services_module,
        "observe_workspace_freshness",
        lambda *_args, **_kwargs: WorkspaceFreshness(
            WorkspaceFreshnessCode.FRESH,
            "fresh",
        ),
    )
    monkeypatch.setattr(
        services,
        "_resolved_live_mutation_path",
        lambda *_args, **_kwargs: relative,
    )
    monkeypatch.setattr(
        services,
        "_observe_live_mutation_context",
        lambda *_args, **_kwargs: (
            _PRE_WORKSPACE_FINGERPRINT,
            _PRE_CONTEXT_FINGERPRINT,
        ),
    )

    services.consume(
        "apply_locator_heal",
        {"proposal_evidence_id": "proposal-evidence-id"},
    )

    assert subject.pending_mutation is not None
    assert subject.pending_mutation.relative_path == relative
    assert subject.pending_mutation.candidate_required is True
    assert subject.pending_mutation.candidate_sha256 is None
    assert subject.pending_mutation.pre_mutation_workspace_fingerprint == _PRE_WORKSPACE_FINGERPRINT
    assert subject.pending_mutation.pre_mutation_context_fingerprint == _PRE_CONTEXT_FINGERPRINT
    assert target.read_bytes() == original


class _FakeEvidence:
    def __init__(self, *items: EvidenceItem) -> None:
        self._items = {item.id: item for item in items}

    def get(self, evidence_id: str) -> EvidenceItem:
        return self._items[evidence_id]


def _live_services_for_evidence(
    tmp_path: Path,
    subject: RuntimeControl,
    state: AgentRunState,
    evidence: _FakeEvidence,
) -> LiveRuntimeServices:
    store = StateStore(subject.metadata_path.parent / "state.json")
    store.save(state)
    return LiveRuntimeServices(
        workspace=subject.workspace,
        state=state,
        evidence=cast(Any, evidence),
        policy=PolicyEngine(tmp_path / "control-provenance", subject.workspace, allow_test_writes=True),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=subject.workspace_identity,
        control=subject,
    )


def test_live_locator_proposal_from_other_run_is_rejected_before_authority_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = _control(tmp_path)
    relative, _target, _original = _existing_target(subject)
    proposal = EvidenceItem(
        id="proposal-cross-run",
        run_id="run-other",
        kind=EvidenceKind.HEALING_PROPOSAL,
        nature=EvidenceNature.MODEL_INTERPRETATION,
        source="self_healing_engine",
        source_identifier="repair-subject",
        summary="cross-run proposal must not authorize mutation",
        structured_data={"repair_subject_id": "repair-subject", "path": relative},
    )
    state = AgentRunState(
        run_id="run-current",
        objective="reject cross-run mutation proposal",
        workspace=str(subject.workspace),
        target_git_sha="a" * 40,
        evidence_ids=[proposal.id],
    )
    services = _live_services_for_evidence(tmp_path, subject, state, _FakeEvidence(proposal))
    resolver_called = False

    def forbidden_resolver(**_kwargs: object) -> object:
        nonlocal resolver_called
        resolver_called = True
        return SimpleNamespace(path=relative)

    monkeypatch.setattr(live_services_module, "resolve_locator_repair_authority", forbidden_resolver)

    with pytest.raises(PermissionError, match="same-run provenance"):
        services._resolved_live_mutation_path(
            "apply_locator_heal",
            {"proposal_evidence_id": proposal.id},
        )

    assert resolver_called is False


def test_candidate_diff_from_different_proposal_cannot_bind_active_mutation(
    tmp_path: Path,
) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 'active proposal'\n"
    _prepare_strict(subject, relative)
    target.write_bytes(candidate)

    stale_diff = EvidenceItem(
        id="diff-stale-proposal",
        run_id="run-current",
        kind=EvidenceKind.GIT_DIFF,
        nature=EvidenceNature.OBSERVED_FACT,
        source="safe_test_patcher",
        source_identifier="proposal-stale",
        summary="same-path diff from a different proposal",
        structured_data={
            "path": relative,
            "new_sha256": _sha256(candidate),
            "proposal_evidence_id": "proposal-stale",
        },
    )
    state = AgentRunState(
        run_id="run-current",
        objective="bind only active proposal candidate evidence",
        workspace=str(subject.workspace),
        target_git_sha="a" * 40,
        evidence_ids=[stale_diff.id],
    )
    services = _live_services_for_evidence(tmp_path, subject, state, _FakeEvidence(stale_diff))
    services._active_mutation_proposal_id = "proposal-active"

    with pytest.raises(RuntimeError, match="no exact candidate evidence"):
        services._bind_active_mutation_candidate()

    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 is None
    assert target.read_bytes() == candidate
