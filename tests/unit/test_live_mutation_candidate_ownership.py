from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.live_services as live_services_module
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import MutationPendingError, RuntimeControl
from ai_qa_automation.runtime.workspace_freshness import (
    WorkspaceFreshness,
    WorkspaceFreshnessCode,
)
from ai_qa_automation.state import StateStore


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


def test_strict_rollback_preserves_newer_independent_writer_bytes(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 1 == 1\n"
    independent = b"def test_target():\n    assert 'newer independent work'\n"

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
    target.write_bytes(candidate)
    subject.bind_pending_mutation_candidate(relative, _sha256(candidate))
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

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
    target.write_bytes(candidate)
    subject.bind_pending_mutation_candidate(relative, _sha256(candidate))
    target.write_bytes(independent)

    with pytest.raises(MutationPendingError, match="no longer matches owned candidate bytes"):
        subject.commit_pending_mutation()

    assert target.read_bytes() == independent
    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 == _sha256(candidate)


def test_strict_rollback_restores_exact_owned_candidate(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, original = _existing_target(subject)
    candidate = b"def test_target():\n    assert 3 == 3\n"

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
    target.write_bytes(candidate)
    subject.bind_pending_mutation_candidate(relative, _sha256(candidate))

    assert subject.rollback_pending_mutation(reason="semantic validation failed") == relative
    assert target.read_bytes() == original
    assert subject.pending_mutation is None


def test_strict_rollback_closes_safely_when_existing_target_never_changed(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, original = _existing_target(subject)

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)

    assert subject.rollback_pending_mutation(reason="tool failed before write") == relative
    assert target.read_bytes() == original
    assert subject.pending_mutation is None


def test_strict_rollback_closes_safely_when_new_target_was_never_created(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative = "tests/test_new.py"
    target = subject.workspace / relative

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)

    assert subject.rollback_pending_mutation(reason="tool failed before write") == relative
    assert not target.exists()
    assert subject.pending_mutation is None


def test_strict_unbound_changed_target_refuses_destructive_rollback(tmp_path: Path) -> None:
    subject = _control(tmp_path)
    relative, target, _original = _existing_target(subject)
    unbound = b"def test_target():\n    assert 'write before ownership bind'\n"

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
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

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
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

    subject.prepare_mutation(relative, change_revision_before=0, candidate_required=True)
    target.write_bytes(candidate)

    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        subject.bind_pending_mutation_candidate(relative, cast(Any, 123))

    assert subject.pending_mutation is not None
    assert subject.pending_mutation.candidate_sha256 is None


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

    services.consume(
        "apply_locator_heal",
        {"proposal_evidence_id": "proposal-evidence-id"},
    )

    assert subject.pending_mutation is not None
    assert subject.pending_mutation.relative_path == relative
    assert subject.pending_mutation.candidate_required is True
    assert subject.pending_mutation.candidate_sha256 is None
    assert target.read_bytes() == original
