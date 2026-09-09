from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import ai_qa_automation.runtime.strict_mutation_publish as strict_publish_module
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceItem,
    EvidenceKind,
    EvidenceNature,
    TerminalStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import MutationPendingError, RuntimeControl
from ai_qa_automation.runtime.strict_mutation_publish import (
    mutation_publication_original_proof_relative_path,
    publish_pending_candidate,
)
from ai_qa_automation.state import StateStore

_PRE_WORKSPACE_FINGERPRINT = "sha256:" + "1" * 64
_PRE_CONTEXT_FINGERPRINT = "sha256:" + "2" * 64
_CANDIDATE_WORKSPACE_FINGERPRINT = "sha256:" + "3" * 64


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "workspace"
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
        lease_id="lease-strict-mutation-publication",
        expected_workspace_fingerprint=_PRE_WORKSPACE_FINGERPRINT,
    )


def _prepare_existing(control: RuntimeControl) -> tuple[str, Path, bytes]:
    relative = "tests/test_target.py"
    target = control.workspace / relative
    target.parent.mkdir(parents=True)
    original = b"def test_target():\n    assert True\n"
    target.write_bytes(original)
    control.prepare_mutation(
        relative,
        change_revision_before=0,
        candidate_required=True,
        pre_mutation_context_fingerprint=_PRE_CONTEXT_FINGERPRINT,
    )
    return relative, target, original


def test_publish_claims_exact_original_and_binds_candidate(tmp_path: Path) -> None:
    control = _control(tmp_path)
    relative, target, original = _prepare_existing(control)
    candidate = b"def test_target():\n    assert 2 + 2 == 4\n"

    candidate_sha256 = publish_pending_candidate(
        control,
        relative_path=relative,
        expected_original_sha256=_sha256(original),
        candidate_bytes=candidate,
    )

    assert candidate_sha256 == _sha256(candidate)
    assert target.read_bytes() == candidate
    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 == candidate_sha256
    proof = control.metadata_path.parent / mutation_publication_original_proof_relative_path(
        relative,
        candidate_sha256,
    )
    assert not proof.exists()


def test_publish_restores_independent_writer_that_changed_target_before_claim(
    tmp_path: Path,
) -> None:
    control = _control(tmp_path)
    relative, target, original = _prepare_existing(control)
    candidate = b"def test_target():\n    assert 1 == 1\n"
    independent = b"def test_target():\n    assert 'independent writer'\n"
    target.write_bytes(independent)

    with pytest.raises(MutationPendingError, match="changed after authorization"):
        publish_pending_candidate(
            control,
            relative_path=relative,
            expected_original_sha256=_sha256(original),
            candidate_bytes=candidate,
        )

    assert target.read_bytes() == independent
    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 is None
    proof = control.metadata_path.parent / mutation_publication_original_proof_relative_path(
        relative,
        _sha256(candidate),
    )
    assert not proof.exists()


def test_publish_preserves_writer_repopulating_after_atomic_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _control(tmp_path)
    relative, target, original = _prepare_existing(control)
    candidate = b"def test_target():\n    assert 3 == 3\n"
    independent = b"def test_target():\n    assert 'writer after claim'\n"
    real_write = strict_publish_module.atomic_write_bytes_confined

    def racing_create(*args: Any, **kwargs: Any) -> None:
        target.write_bytes(independent)
        real_write(*args, **kwargs)

    monkeypatch.setattr(strict_publish_module, "atomic_write_bytes_confined", racing_create)

    with pytest.raises(MutationPendingError, match="concurrently repopulated"):
        publish_pending_candidate(
            control,
            relative_path=relative,
            expected_original_sha256=_sha256(original),
            candidate_bytes=candidate,
        )

    assert target.read_bytes() == independent
    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 is None
    proof = control.metadata_path.parent / mutation_publication_original_proof_relative_path(
        relative,
        _sha256(candidate),
    )
    assert proof.read_bytes() == original


class _FakeEvidence:
    def __init__(self, *items: EvidenceItem) -> None:
        self._items = {item.id: item for item in items}

    def get(self, evidence_id: str) -> EvidenceItem:
        return self._items[evidence_id]


def _live_services(
    tmp_path: Path,
    control: RuntimeControl,
    state: AgentRunState,
    evidence: _FakeEvidence,
) -> LiveRuntimeServices:
    store = StateStore(control.metadata_path.parent / "state.json")
    store.save(state)
    return LiveRuntimeServices(
        workspace=control.workspace,
        state=state,
        evidence=cast(Any, evidence),
        policy=PolicyEngine(tmp_path / "control", control.workspace, allow_test_writes=True),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=control.workspace_identity,
        control=control,
    )


def test_prebound_candidate_still_requires_exact_same_run_diff_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _control(tmp_path)
    relative, _target, original = _prepare_existing(control)
    candidate = b"def test_target():\n    assert 4 == 4\n"
    candidate_sha256 = publish_pending_candidate(
        control,
        relative_path=relative,
        expected_original_sha256=_sha256(original),
        candidate_bytes=candidate,
    )
    proposal_id = "proposal-active"
    diff = EvidenceItem(
        id="diff-active",
        run_id="run-current",
        kind=EvidenceKind.GIT_DIFF,
        nature=EvidenceNature.OBSERVED_FACT,
        source="safe_test_patcher",
        source_identifier=proposal_id,
        summary="exact strict publication candidate",
        structured_data={
            "path": relative,
            "new_sha256": candidate_sha256,
            "proposal_evidence_id": proposal_id,
        },
    )
    state = AgentRunState(
        run_id="run-current",
        objective="bind exact pre-published candidate evidence",
        workspace=str(control.workspace),
        target_git_sha="a" * 40,
        evidence_ids=[diff.id],
    )
    services = _live_services(tmp_path, control, state, _FakeEvidence(diff))
    services._active_mutation_proposal_id = proposal_id
    monkeypatch.setattr(
        services,
        "_observe_live_mutation_context",
        lambda *_args, **_kwargs: (
            _CANDIDATE_WORKSPACE_FINGERPRINT,
            _PRE_CONTEXT_FINGERPRINT,
        ),
    )

    services._bind_active_mutation_candidate()

    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 == candidate_sha256
    assert pending.candidate_workspace_fingerprint == _CANDIDATE_WORKSPACE_FINGERPRINT
    assert control.expected_workspace_fingerprint == _CANDIDATE_WORKSPACE_FINGERPRINT


def test_prebound_candidate_rejects_mismatched_diff_evidence(tmp_path: Path) -> None:
    control = _control(tmp_path)
    relative, target, original = _prepare_existing(control)
    candidate = b"def test_target():\n    assert 5 == 5\n"
    candidate_sha256 = publish_pending_candidate(
        control,
        relative_path=relative,
        expected_original_sha256=_sha256(original),
        candidate_bytes=candidate,
    )
    proposal_id = "proposal-active"
    diff = EvidenceItem(
        id="diff-mismatch",
        run_id="run-current",
        kind=EvidenceKind.GIT_DIFF,
        nature=EvidenceNature.OBSERVED_FACT,
        source="safe_test_patcher",
        source_identifier=proposal_id,
        summary="mismatched candidate evidence",
        structured_data={
            "path": relative,
            "new_sha256": "0" * 64,
            "proposal_evidence_id": proposal_id,
        },
    )
    state = AgentRunState(
        run_id="run-current",
        objective="reject mismatched pre-published candidate evidence",
        workspace=str(control.workspace),
        target_git_sha="a" * 40,
        evidence_ids=[diff.id],
    )
    services = _live_services(tmp_path, control, state, _FakeEvidence(diff))
    services._active_mutation_proposal_id = proposal_id

    with pytest.raises(RuntimeError, match="runtime-bound candidate bytes do not match"):
        services._bind_active_mutation_candidate()

    assert target.read_bytes() == candidate
    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 == candidate_sha256
    assert state.terminal_status is TerminalStatus.BLOCKED


def test_live_consume_preserves_writer_during_post_prepare_reproof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _control(tmp_path)
    relative = "tests/test_target.py"
    target = control.workspace / relative
    target.parent.mkdir(parents=True)
    original = b"def test_target():\n    assert True\n"
    independent = b"def test_target():\n    assert 'writer during preparation'\n"
    target.write_bytes(original)
    proposal_id = "proposal-preparation-race"
    repair_subject_id = "repair-preparation-race"
    proposal = EvidenceItem(
        id=proposal_id,
        run_id="run-current",
        kind=EvidenceKind.HEALING_PROPOSAL,
        nature=EvidenceNature.MODEL_INTERPRETATION,
        source="self_healing_engine",
        source_identifier=repair_subject_id,
        summary="evidence-bound preparation race fixture",
        structured_data={
            "repair_subject_id": repair_subject_id,
            "path": relative,
            "expected_sha256": _sha256(original),
        },
    )
    state = AgentRunState(
        run_id="run-current",
        objective="preserve writer during strict mutation preparation",
        workspace=str(control.workspace),
        target_git_sha="a" * 40,
        evidence_ids=[proposal.id],
    )
    services = _live_services(tmp_path, control, state, _FakeEvidence(proposal))
    monkeypatch.setattr(services, "_require_workspace_freshness", lambda **_kwargs: None)
    monkeypatch.setattr(
        strict_publish_module,
        "publish_pending_candidate",
        strict_publish_module.publish_pending_candidate,
    )
    monkeypatch.setattr(
        __import__("ai_qa_automation.runtime.live_services", fromlist=["x"]),
        "resolve_locator_repair_authority",
        lambda **_kwargs: SimpleNamespace(
            path=relative,
            expected_sha256=_sha256(original),
        ),
    )
    observations = 0

    def observe(_relative_path: str) -> tuple[str, str]:
        nonlocal observations
        observations += 1
        if observations == 1:
            return _PRE_WORKSPACE_FINGERPRINT, _PRE_CONTEXT_FINGERPRINT
        target.write_bytes(independent)
        return "sha256:" + "9" * 64, _PRE_CONTEXT_FINGERPRINT

    monkeypatch.setattr(services, "_observe_live_mutation_context", observe)

    with pytest.raises(RuntimeError, match="workspace changed while strict mutation"):
        services.consume("apply_locator_heal", {"proposal_evidence_id": proposal_id})

    assert target.read_bytes() == independent
    assert control.pending_mutation is not None
    assert control.pending_mutation.candidate_sha256 is None
    assert state.terminal_status is TerminalStatus.BLOCKED
