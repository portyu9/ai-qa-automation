from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import (
    PendingMutation,
    RuntimeControl,
    atomic_write_json,
)
from ai_qa_automation.runtime.runtime_hooks import (
    _reconcile_rolled_back_mutation,
    posttool_policy_output,
    pretool_policy_output,
)
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.tools.repository import RepositoryInspector


def _control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-final-hardening"
    return RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=5,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-final-hardening",
    )


def test_fingerprint_marks_changed_file_overflow_incomplete(tmp_path: Path) -> None:
    inspector = RepositoryInspector(tmp_path)
    changed = tuple(f"tests/test_{index:04d}.py" for index in range(1001))

    _fingerprint, complete, reasons = inspector._fingerprint(None, "", changed)

    assert complete is False
    assert "changed-file-limit-exceeded" in reasons


def test_fingerprint_marks_changed_symlink_incomplete(tmp_path: Path) -> None:
    target = tmp_path / "real.py"
    target.write_text("value = 1\n", encoding="utf-8")
    link = tmp_path / "tests" / "test_link.py"
    link.parent.mkdir()
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    inspector = RepositoryInspector(tmp_path)
    _fingerprint, complete, reasons = inspector._fingerprint(
        None,
        " M tests/test_link.py",
        ("tests/test_link.py",),
    )

    assert complete is False
    assert "changed-symlink-not-byte-bound" in reasons


def test_mutation_denies_incomplete_workspace_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    control = _control(tmp_path)
    control.expected_workspace_fingerprint = "sha256:baseline"
    policy = PolicyEngine(tmp_path, control.workspace, allow_test_writes=True)
    state = AgentRunState(
        objective="mutate",
        workspace=str(control.workspace),
        target_git_sha="a" * 40,
    )

    class FakeInspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self) -> SimpleNamespace:
            return SimpleNamespace(
                fingerprint="sha256:baseline",
                fingerprint_complete=False,
                fingerprint_incomplete_reasons=("changed-file-limit-exceeded",),
            )

    monkeypatch.setattr(
        "ai_qa_automation.runtime.runtime_hooks.RepositoryInspector",
        FakeInspector,
    )

    result = pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__create_test_file",
            "tool_input": {"path": "tests/test_generated.py"},
        },
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert "fingerprint coverage is incomplete" in hook["permissionDecisionReason"]
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.pending_mutation is None


def test_post_mutation_incomplete_fingerprint_rolls_candidate_back(
    tmp_path: Path,
    monkeypatch,
) -> None:
    control = _control(tmp_path)
    generated = control.workspace / "tests" / "test_generated.py"
    generated.parent.mkdir()
    generated.write_text("def test_generated():\n    assert True\n", encoding="utf-8")
    state = AgentRunState(
        objective="generate",
        workspace=str(control.workspace),
        target_git_sha="a" * 40,
        change_revision=1,
        files_modified=["tests/test_generated.py"],
    )
    control.pending_mutation = PendingMutation(
        relative_path="tests/test_generated.py",
        existed=False,
        backup_path=None,
        original_sha256=None,
        change_revision_before=0,
    )

    snapshots = iter(
        [
            SimpleNamespace(
                fingerprint="sha256:candidate",
                fingerprint_complete=False,
                fingerprint_incomplete_reasons=("changed-file-limit-exceeded",),
            ),
            SimpleNamespace(
                fingerprint="sha256:restored",
                fingerprint_complete=True,
                fingerprint_incomplete_reasons=(),
            ),
        ]
    )

    class FakeInspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self) -> SimpleNamespace:
            return next(snapshots)

    monkeypatch.setattr(
        "ai_qa_automation.runtime.runtime_hooks.RepositoryInspector",
        FakeInspector,
    )

    result = posttool_policy_output(
        {
            "tool_name": "mcp__qa__create_test_file",
            "tool_response": {"path": "tests/test_generated.py"},
        },
        state=state,
        control=control,
    )

    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.pending_mutation is None
    assert control.expected_workspace_fingerprint == "sha256:restored"
    assert not generated.exists()
    assert state.files_modified == []
    assert state.validation_results[-1].status is ValidationStatus.NOT_VERIFIED


def test_rollback_reconciliation_removes_only_advanced_attempt(tmp_path: Path) -> None:
    state = AgentRunState(objective="repair", workspace=str(tmp_path), change_revision=2)
    state.files_modified = [
        "tests/test_checkout.py",
        "tests/test_other.py",
        "tests/test_checkout.py",
    ]
    pending = PendingMutation(
        relative_path="tests/test_checkout.py",
        existed=True,
        backup_path=None,
        original_sha256=None,
        change_revision_before=1,
    )

    _reconcile_rolled_back_mutation(state, pending, "tests/test_checkout.py")

    assert state.files_modified == ["tests/test_checkout.py", "tests/test_other.py"]
    assert state.change_revision == 2
    assert any("modified-file accounting was reconciled" in item for item in state.observations)
    rollback_gate = state.validation_results[-1]
    assert rollback_gate.gate_id == "mutation_transaction:tests/test_checkout.py"
    assert rollback_gate.revision == 2
    assert rollback_gate.status is ValidationStatus.NOT_VERIFIED


def test_rollback_reconciliation_preserves_prior_commit_when_attempt_never_advanced(
    tmp_path: Path,
) -> None:
    state = AgentRunState(objective="repair", workspace=str(tmp_path), change_revision=1)
    state.files_modified = ["tests/test_checkout.py"]
    pending = PendingMutation(
        relative_path="tests/test_checkout.py",
        existed=True,
        backup_path=None,
        original_sha256=None,
        change_revision_before=1,
    )

    _reconcile_rolled_back_mutation(state, pending, "tests/test_checkout.py")

    assert state.files_modified == ["tests/test_checkout.py"]
    assert state.observations == []
    assert state.validation_results == []


def test_runtime_atomic_write_rejects_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text('{"owned": true}\n', encoding="utf-8")
    runtime_path = tmp_path / "run" / "runtime.json"
    runtime_path.parent.mkdir()
    try:
        runtime_path.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RuntimeError, match="atomic write target is a symlink"):
        atomic_write_json(runtime_path, {"owned": False})

    assert outside.read_text(encoding="utf-8") == '{"owned": true}\n'


def test_incomplete_fingerprint_does_not_block_prior_run_without_pending_mutation(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    (prior_run / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(workspace.resolve()),
                "workspace_fingerprint": "sha256:prior",
                "pending_mutation": None,
            }
        ),
        encoding="utf-8",
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="sha256:current",
        current_workspace_fingerprint_complete=False,
        current_workspace_fingerprint_reasons=("changed-file-limit-exceeded",),
        recovering_run_id="run-new",
    )

    assert result == {"status": "NONE", "previous_run_id": "run-old"}


def test_incomplete_fingerprint_blocks_real_stale_pending_mutation(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_generated.py"
    target.parent.mkdir()
    target.write_text("generated but unverified\n", encoding="utf-8")
    prior_run = artifact_root / "run-old"
    prior_run.mkdir(parents=True)
    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    (prior_run / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(workspace.resolve()),
                "workspace_fingerprint": "sha256:prior",
                "journal_event_count": journal.event_count,
                "journal_head_hash": journal.head_hash,
                "pending_mutation": {
                    "relative_path": "tests/test_generated.py",
                    "existed": False,
                    "backup_path": None,
                    "original_sha256": None,
                },
            }
        ),
        encoding="utf-8",
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="sha256:prior",
        current_workspace_fingerprint_complete=False,
        current_workspace_fingerprint_reasons=("changed-file-limit-exceeded",),
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "fingerprint is incomplete" in result["reason"]
    assert target.exists()
