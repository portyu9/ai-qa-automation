from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.internal_tools import _stable_gate_id
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def make_services(
    tmp_path: Path,
    *,
    external_egress: bool,
) -> tuple[LiveRuntimeServices, RuntimeControl, StateStore]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(objective="run target k6 safely", workspace=str(workspace))
    store = StateStore(run_dir / "state.json")
    control = RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=10,
            max_mutations=3,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-k6-isolation",
        max_repeated_action=3,
    )
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, object()),
        max_tool_calls=10,
        max_repeated_action=3,
        k6_external_egress_enforced=external_egress,
        state_store=store,
        workspace_root_identity=pin_directory_identity(workspace, label="test workspace"),
        control=control,
    )
    return services, control, store


def _request() -> dict[str, object]:
    return {
        "script": "performance/load.js",
        "target_url": "http://127.0.0.1:8000",
        "environment": "local",
        "max_p95_ms": 500.0,
        "max_error_rate": 0.01,
        "min_request_rate": 1.0,
    }


@pytest.mark.parametrize(
    ("external_egress", "missing_text"),
    [
        (False, "process/filesystem isolation and outbound-egress enforcement"),
        (True, "process/filesystem isolation"),
    ],
)
def test_live_k6_blocks_and_persists_authority_gate_before_execution(
    tmp_path: Path,
    external_egress: bool,
    missing_text: str,
) -> None:
    services, control, store = make_services(tmp_path, external_egress=external_egress)
    control.budget.charge_tool()
    request = _request()

    with pytest.raises(PermissionError, match="k6 target-code execution requires"):
        services.consume("run_k6", request)

    assert services.state.tool_call_count == 1
    assert services.state.terminal_status is TerminalStatus.BLOCKED
    assert services.state.terminal_reason is not None
    assert missing_text in services.state.terminal_reason
    assert len(services.state.validation_results) == 1
    validation = services.state.validation_results[0]
    assert validation.name == "k6"
    assert validation.status is ValidationStatus.BLOCKED
    assert validation.gate_id == _stable_gate_id("k6", request)
    assert validation.details == {
        **request,
        "execution_started": False,
        "process_isolation_enforced": False,
        "external_egress_enforced": external_egress,
    }

    persisted = store.load()
    assert persisted.tool_call_count == 1
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert persisted.validation_results[0].status is ValidationStatus.BLOCKED
    assert persisted.validation_results[0].gate_id == validation.gate_id
    assert persisted.validation_results[0].details["execution_started"] is False


def test_live_k6_gate_identity_includes_threshold_contract(tmp_path: Path) -> None:
    services, control, _ = make_services(tmp_path, external_egress=True)
    control.budget.charge_tool()
    first = _request()

    with pytest.raises(PermissionError):
        services.consume("run_k6", first)
    first_gate = services.state.validation_results[-1].gate_id

    second = _request()
    second["max_p95_ms"] = 750.0
    control.budget.charge_tool()
    with pytest.raises(PermissionError):
        services.consume("run_k6", second)
    second_gate = services.state.validation_results[-1].gate_id

    assert first_gate != second_gate
