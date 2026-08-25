from __future__ import annotations

from pathlib import Path

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, MCPStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.runtime.runtime_hooks import posttool_failure_output, posttool_policy_output
from ai_qa_automation.runtime.tool_output_bounds import (
    MAX_EXTERNAL_FAILURE_MESSAGE_UTF8_BYTES,
    MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES,
)


class Explosive:
    def __str__(self) -> str:
        raise AssertionError("untrusted output was stringified")


def test_oversized_success_becomes_invalid_response_without_evidence(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {"body": "x" * (MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES + 1)},
        },
        state=state,
        evidence=evidence,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE
    assert state.evidence_ids == []
    assert state.external_evidence == []
    hook = result["hookSpecificOutput"]
    assert hook["updatedToolOutput"]["is_error"] is True
    assert hook["updatedToolOutput"]["reason_code"] == "utf8_bytes"
    assert "No successful remote evidence" in hook["additionalContext"]


def test_oversized_error_shaped_result_cannot_be_normalized_as_rate_limit(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {
                "is_error": True,
                "error": "HTTP 429 rate limit exceeded",
                "body": "x" * (MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES + 1),
            },
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE


def test_failure_metadata_is_not_arbitrarily_stringified(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    result = posttool_failure_output(
        {"tool_name": "mcp__github__get_issue", "error": Explosive()},
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE
    assert "INVALID_RESPONSE" in result["hookSpecificOutput"]["additionalContext"]


def test_oversized_failure_message_is_invalid_response(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    posttool_failure_output(
        {
            "tool_name": "mcp__github__get_issue",
            "error": "x" * (MAX_EXTERNAL_FAILURE_MESSAGE_UTF8_BYTES + 1),
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE


def test_bounded_http_429_failure_keeps_existing_normalization(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    posttool_failure_output(
        {"tool_name": "mcp__github__get_issue", "error": "HTTP 429 rate limit exceeded"},
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.RATE_LIMITED


class ExplosiveBool:
    def __bool__(self) -> bool:
        raise AssertionError("unvalidated provider error flag was evaluated")


def test_error_flag_is_not_evaluated_before_output_validation(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {"is_error": ExplosiveBool()},
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE
    assert result["hookSpecificOutput"]["updatedToolOutput"]["reason_code"] == "value_type"


def test_normal_success_remains_sanitized_observed_evidence(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)
    secret = "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv"  # pragma: allowlist secret

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {"authorization": f"Bearer {secret}"},
            "tool_response": {"title": "ok", "token": secret, "body": f"token={secret}"},
        },
        state=state,
        evidence=evidence,
    )

    assert state.mcp_status["github"] is MCPStatus.AVAILABLE
    assert len(state.external_evidence) == 1
    assert secret not in str(result)
    item = evidence.get(state.external_evidence[0])
    assert secret not in str(item.structured_data)


def test_non_boolean_error_flag_is_invalid_response(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {"is_error": "false", "body": "not a valid error flag"},
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.INVALID_RESPONSE
    assert result["hookSpecificOutput"]["updatedToolOutput"]["reason_code"] == "error_flag_type"


def test_error_shaped_bounded_result_preserves_rate_limit_normalization(tmp_path: Path) -> None:
    state = AgentRunState(objective="read issue", workspace=str(tmp_path))

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {"is_error": True, "error": "HTTP 429 rate limit exceeded"},
        },
        state=state,
    )

    assert state.mcp_status["github"] is MCPStatus.RATE_LIMITED
    assert state.evidence_ids == []
    assert result["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True


def test_output_rejection_counts_as_runtime_failure_without_journaling_response(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "runtime"
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=5,
            max_network_calls=5,
            max_mutations=1,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="output-bound-test",
        circuit_failure_threshold=1,
    )
    state = AgentRunState(objective="read issue", workspace=str(workspace))
    marker = "response-secret-marker"

    result = posttool_policy_output(
        {
            "tool_name": "mcp__github__get_issue",
            "tool_input": {},
            "tool_response": {"body": marker + ("x" * (MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES + 1))},
        },
        state=state,
        control=control,
    )

    assert result["hookSpecificOutput"]["updatedToolOutput"]["is_error"] is True
    assert control.circuit_failures["mcp__github__get_issue"] == 1
    assert "mcp__github__get_issue" in control.open_circuits
    journal = control.journal.path.read_text(encoding="utf-8")
    assert marker not in journal
    assert "tool_output_denied" in journal
    assert "utf8_bytes" in journal
