from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, cast

import pytest

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
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.strict_mutation_publish import publish_pending_candidate
from ai_qa_automation.state import StateStore

_PRE_WORKSPACE_FINGERPRINT = "sha256:" + "1" * 64
_PRE_CONTEXT_FINGERPRINT = "sha256:" + "2" * 64
_CANDIDATE_WORKSPACE_FINGERPRINT = "sha256:" + "3" * 64


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Evidence:
    def __init__(self, item: EvidenceItem) -> None:
        self.item = item

    def get(self, evidence_id: str) -> EvidenceItem:
        if evidence_id != self.item.id:
            raise KeyError(evidence_id)
        return self.item


def test_candidate_drift_before_workspace_binding_is_durably_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    relative = "tests/test_target.py"
    target = workspace / relative
    target.parent.mkdir(parents=True)
    original = b"def test_target():\n    assert True\n"
    candidate = b"def test_target():\n    assert 6 == 6\n"
    independent = b"def test_target():\n    assert 'independent after patch evidence'\n"
    target.write_bytes(original)

    run_dir = tmp_path / "run"
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-live-candidate-binding-drift",
        expected_workspace_fingerprint=_PRE_WORKSPACE_FINGERPRINT,
    )
    control.prepare_mutation(
        relative,
        change_revision_before=0,
        candidate_required=True,
        pre_mutation_context_fingerprint=_PRE_CONTEXT_FINGERPRINT,
    )
    candidate_sha256 = publish_pending_candidate(
        control,
        relative_path=relative,
        expected_original_sha256=_sha256(original),
        candidate_bytes=candidate,
    )

    proposal_id = "proposal-candidate-binding-drift"
    diff = EvidenceItem(
        id="diff-candidate-binding-drift",
        run_id="run-current",
        kind=EvidenceKind.GIT_DIFF,
        nature=EvidenceNature.OBSERVED_FACT,
        source="safe_test_patcher",
        source_identifier=proposal_id,
        summary="candidate whose target changes before workspace binding",
        structured_data={
            "path": relative,
            "new_sha256": candidate_sha256,
            "proposal_evidence_id": proposal_id,
        },
    )
    state = AgentRunState(
        run_id="run-current",
        objective="block candidate ownership drift before workspace binding",
        workspace=str(workspace),
        target_git_sha="a" * 40,
        evidence_ids=[diff.id],
    )
    store = StateStore(run_dir / "state.json")
    store.save(state)
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=cast(Any, _Evidence(diff)),
        policy=PolicyEngine(tmp_path / "control", workspace, allow_test_writes=True),
        test_runner=cast(Any, object()),
        max_tool_calls=20,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=control.workspace_identity,
        control=control,
    )
    services._active_mutation_proposal_id = proposal_id
    monkeypatch.setattr(
        services,
        "_observe_live_mutation_context",
        lambda *_args, **_kwargs: (
            _CANDIDATE_WORKSPACE_FINGERPRINT,
            _PRE_CONTEXT_FINGERPRINT,
        ),
    )
    target.write_bytes(independent)

    with pytest.raises(RuntimeError, match="candidate ownership changed"):
        services._bind_active_mutation_candidate()

    assert target.read_bytes() == independent
    pending = control.pending_mutation
    assert pending is not None
    assert pending.candidate_sha256 == candidate_sha256
    assert pending.candidate_workspace_fingerprint is None
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert store.load().terminal_status is TerminalStatus.BLOCKED
