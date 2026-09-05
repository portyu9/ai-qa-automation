from __future__ import annotations

from pathlib import Path

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.state import StateStore

_LEGACY_RUNTIME_KEYS = {
    "agent_version",
    "model_id",
    "sdk_version",
    "policy_version",
    "tool_schema_version",
    "configuration_version",
}


def test_v1_attestation_preserves_legacy_runtime_shape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(
        objective="verify legacy attestation schema compatibility",
        workspace=str(workspace),
        terminal_status=TerminalStatus.NOT_VERIFIED,
        terminal_reason="legacy state contains no control-plane provenance",
    )
    StateStore(run_dir / "state.json").save(state)

    attestation = build_run_attestation(run_dir)

    assert attestation["schema"] == "ai-qa-run-attestation/v1"
    assert set(attestation["runtime"]) == _LEGACY_RUNTIME_KEYS
    assert "control_plane_subject" not in attestation["runtime"]
    assert "control_plane_revalidation_status" not in attestation["runtime"]
    assert "control_plane_terminal_subject_digest" not in attestation["runtime"]
