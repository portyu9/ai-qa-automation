from __future__ import annotations

from pathlib import Path

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import (
    AgentRunState,
    EvidenceKind,
    EvidenceNature,
    MCPStatus,
    TerminalStatus,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import (
    posttool_failure_output,
    posttool_policy_output,
    pretool_policy_output,
)


def make_control(tmp_path: Path, *, max_tool_calls: int = 20) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir(exist_ok=True)
    run_dir = tmp_path / "artifacts" / "run-hooks"
    return RuntimeControl(
        workspace=workspace.resolve(),
        budget=ExecutionBudget(
            max_tool_calls=max_tool_calls,
            max_network_calls=10,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-hooks",
    )


def test_pretool_budget_denial_sets_terminal_state_and_fails_closed(tmp_path: Path) -> None:
    control = make_control(tmp_path, max_tool_calls=1)
    policy = PolicyEngine(tmp_path, control.workspace)
    state = AgentRunState(objective="bounded", workspace=str(control.workspace))

    first = pretool_policy_output(
        policy,
        {"tool_name": "mcp__qa__inspect_repository", "tool_input": {}},
        state=state,
        control=control,
    )
    assert first == {}

    second = pretool_policy_output(
        policy,
        {"tool_name": "mcp__qa__inspect_repository", "tool_input": {}},
        state=state,
        control=control,
    )

    hook = second["hookSpecificOutput"]
    assert hook["permissionDecision"] == "deny"
    assert hook["permissionDecisionReason"].startswith("runtime-budget:")
    assert state.terminal_status is TerminalStatus.BUDGET_EXCEEDED
    assert state.terminal_reason


def test_pretool_mutation_without_git_identity_is_blocked_before_write(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    policy = PolicyEngine(tmp_path, control.workspace, allow_test_writes=True)
    state = AgentRunState(objective="mutate", workspace=str(control.workspace), target_git_sha=None)

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
    assert "git-backed" in hook["permissionDecisionReason"]
    assert state.terminal_status is TerminalStatus.BLOCKED
    assert control.pending_mutation is None
    assert not (control.workspace / "tests" / "test_generated.py").exists()


def test_pretool_journal_records_only_fingerprint_not_raw_secret_input(tmp_path: Path) -> None:
    control = make_control(tmp_path)
    policy = PolicyEngine(tmp_path, control.workspace)
    secret = "sk-" + "ant-" + "this-must-never-enter-the-journal"

    result = pretool_policy_output(
        policy,
        {
            "tool_name": "mcp__qa__inspect_repository",
            "tool_input": {"diagnostic_token": secret},
        },
        control=control,
    )

    assert result == {}
    journal_text = control.journal.path.read_text(encoding="utf-8")
    assert secret not in journal_text
    assert "input_hash" in journal_text


def test_external_mcp_success_is_sanitized_and_registered_as_observed_evidence(
    tmp_path: Path,
) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)
    secret = "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv"

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {"authorization": f"Bearer {secret}"},
            "tool_response": {
                "title": "failure",
                "token": secret,
                "body": f"token={secret}",
            },
        },
        state=state,
        evidence=evidence,
    )

    hook = result["hookSpecificOutput"]
    assert secret not in str(hook)
    assert state.mcp_status["github"] is MCPStatus.AVAILABLE
    assert len(state.external_evidence) == 1
    assert state.external_evidence == state.evidence_ids

    item = evidence.get(state.external_evidence[0])
    assert item.kind is EvidenceKind.MCP_RESULT
    assert item.nature is EvidenceNature.OBSERVED_FACT
    assert item.source == "github"
    assert secret not in str(item.structured_data)


def test_external_mcp_error_shaped_result_is_not_promoted_to_available_or_evidence(
    tmp_path: Path,
) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {
                "is_error": True,
                "error": "HTTP 429 rate limit exceeded",
            },
        },
        state=state,
        evidence=evidence,
    )

    assert state.mcp_status["github"] is MCPStatus.RATE_LIMITED
    assert state.evidence_ids == []
    assert state.external_evidence == []
    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert "no successful remote evidence was registered" in hook["additionalContext"]


def test_external_mcp_failure_normalizes_health_without_fabricating_evidence(
    tmp_path: Path,
) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    result = posttool_failure_output(
        {
            "tool_name": "mcp__github__get_issue",
            "error": "HTTP 429 rate limit exceeded",
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.RATE_LIMITED
    assert state.evidence_ids == []
    assert state.external_evidence == []
    assert "no remote evidence was fabricated" in result["hookSpecificOutput"]["additionalContext"]
