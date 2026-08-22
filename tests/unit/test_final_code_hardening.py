from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import PendingMutation, RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import (
    _reconcile_rolled_back_mutation,
    pretool_policy_output,
)
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
    except OSError:
        return

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
