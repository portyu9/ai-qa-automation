from __future__ import annotations

from .models import AgentRunState, FinalAgentReport, TerminalStatus


def build_final_report(state: AgentRunState, *, limitations: list[str] | None = None) -> FinalAgentReport:
    status = state.terminal_status or TerminalStatus.NOT_VERIFIED
    return FinalAgentReport(
        run_id=state.run_id,
        objective=state.objective,
        terminal_status=status,
        summary=state.terminal_reason or "Run ended without a terminal reason.",
        classification=state.classification,
        classification_confidence=state.classification_confidence,
        evidence_ids=state.evidence_ids,
        validation_results=state.validation_results,
        files_modified=state.files_modified,
        limitations=limitations or [],
        provenance={
            "agent_version": state.agent_version,
            "model_id": state.model_id,
            "sdk_version": state.sdk_version,
            "policy_version": state.policy_version,
            "tool_schema_version": state.tool_schema_version,
            "target_git_sha": state.target_git_sha or "NOT_OBSERVED",
        },
    )
