from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ai_qa_automation.fs_authority import pin_directory_identity
from ai_qa_automation.models import AgentRunState, TerminalStatus, ValidationStatus
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.live_services import LiveRuntimeServices
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.pytest_sandbox import PytestSandboxPreflight
from ai_qa_automation.tools.repository import RepositoryInspector


class FakeTestRunner:
    def __init__(self, *, sandbox_ready: bool = True, reason: str | None = None) -> None:
        self.result = PytestSandboxPreflight(
            ready=sandbox_ready,
            backend="bubblewrap",
            reason=reason if not sandbox_ready else None,
            executable="/usr/bin/bwrap" if sandbox_ready else None,
            executable_sha256="sha256:" + "a" * 64 if sandbox_ready else None,
            version="bubblewrap 0.12.0" if sandbox_ready else None,
            parent_namespaces={"mnt": "1", "pid": "2", "net": "3", "user": "4"}
            if sandbox_ready
            else None,
            child_namespaces={"mnt": "5", "pid": "6", "net": "7", "user": "8"}
            if sandbox_ready
            else None,
            workspace_identity_bound=sandbox_ready,
            workspace_read_only=sandbox_ready,
            forbidden_roots_hidden=sandbox_ready,
            no_non_loopback_interfaces=sandbox_ready,
            effective_capabilities_zero=sandbox_ready,
        )
        self.preflight_calls = 0

    def sandbox_preflight(self) -> PytestSandboxPreflight:
        self.preflight_calls += 1
        return self.result


def make_services(
    tmp_path: Path,
    *,
    process_isolation: bool = False,
    external_egress: bool = False,
    sandbox_ready: bool = True,
    sandbox_reason: str | None = None,
) -> tuple[LiveRuntimeServices, RuntimeControl, StateStore, FakeTestRunner]:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
    state = AgentRunState(objective="run target pytest safely", workspace=str(workspace))
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
        lease_id="lease-pytest-isolation",
        max_repeated_action=3,
    )
    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=control.workspace_identity,
    ).snapshot()
    assert snapshot.fingerprint_complete is True
    control.set_workspace_fingerprint(snapshot.fingerprint)
    runner = FakeTestRunner(sandbox_ready=sandbox_ready, reason=sandbox_reason)
    services = LiveRuntimeServices(
        workspace=workspace,
        state=state,
        evidence=cast(Any, object()),
        policy=cast(Any, object()),
        test_runner=cast(Any, runner),
        max_tool_calls=10,
        max_repeated_action=3,
        state_store=store,
        workspace_root_identity=pin_directory_identity(workspace, label="test workspace"),
        control=control,
        pytest_process_isolation_enforced=process_isolation,
        pytest_external_egress_enforced=external_egress,
    )
    return services, control, store, runner


@pytest.mark.parametrize(
    ("process_isolation", "external_egress", "missing_text"),
    [
        (False, False, "process/filesystem isolation and outbound-egress enforcement"),
        (False, True, "process/filesystem isolation"),
        (True, False, "outbound-egress enforcement"),
    ],
)
def test_live_pytest_blocks_before_sandbox_probe_when_deployment_intent_is_missing(
    tmp_path: Path,
    process_isolation: bool,
    external_egress: bool,
    missing_text: str,
) -> None:
    services, control, store, runner = make_services(
        tmp_path,
        process_isolation=process_isolation,
        external_egress=external_egress,
    )
    control.budget.charge_tool()

    with pytest.raises(PermissionError, match="pytest target-code execution requires"):
        services.consume("run_pytest", {"args": ["tests/test_checkout.py"]})

    assert runner.preflight_calls == 0
    assert services.state.tool_call_count == 1
    assert services.state.terminal_status is TerminalStatus.BLOCKED
    assert services.state.terminal_reason is not None
    assert missing_text in services.state.terminal_reason
    assert services.state.tests_executed == []
    assert len(services.state.validation_results) == 1
    validation = services.state.validation_results[0]
    assert validation.name == "pytest"
    assert validation.status is ValidationStatus.BLOCKED
    assert validation.details["scope"] == "targeted"
    assert validation.details["args"] == ["tests/test_checkout.py"]
    assert validation.details["execution_started"] is False
    assert validation.details["process_isolation_enforced"] is process_isolation
    assert validation.details["external_egress_enforced"] is external_egress
    assert validation.details["sandbox"]["preflight_attempted"] is False
    assert validation.gate_id is not None and validation.gate_id.startswith("pytest:")

    persisted = store.load()
    assert persisted.tool_call_count == 1
    assert persisted.terminal_status is TerminalStatus.BLOCKED
    assert persisted.validation_results[0].status is ValidationStatus.BLOCKED
    assert persisted.validation_results[0].details["execution_started"] is False


def test_true_deployment_assertions_do_not_authorize_pytest_without_real_sandbox(
    tmp_path: Path,
) -> None:
    services, control, store, runner = make_services(
        tmp_path,
        process_isolation=True,
        external_egress=True,
        sandbox_ready=False,
        sandbox_reason="Bubblewrap executable is not available on the controlled PATH",
    )
    control.budget.charge_tool()

    with pytest.raises(PermissionError, match="verified OS sandbox"):
        services.consume("run_pytest", {"args": []})

    assert runner.preflight_calls == 1
    assert services.state.terminal_status is TerminalStatus.BLOCKED
    validation = services.state.validation_results[-1]
    assert validation.status is ValidationStatus.BLOCKED
    assert validation.details["execution_started"] is False
    assert validation.details["sandbox"]["preflight_attempted"] is True
    assert validation.details["sandbox"]["ready"] is False
    persisted = store.load()
    assert persisted.validation_results[-1].status is ValidationStatus.BLOCKED


def test_live_pytest_reaches_existing_execution_path_only_after_sandbox_proof(
    tmp_path: Path,
) -> None:
    services, control, _, runner = make_services(
        tmp_path,
        process_isolation=True,
        external_egress=True,
        sandbox_ready=True,
    )
    control.budget.charge_tool()

    services.consume("run_pytest", {"args": []})

    assert runner.preflight_calls == 1
    assert services.state.tool_call_count == 1
    assert services.state.terminal_status is None
    assert services.state.validation_results == []


@pytest.mark.parametrize(
    "field",
    ["pytest_process_isolation_enforced", "pytest_external_egress_enforced"],
)
def test_live_pytest_isolation_assertions_require_real_booleans(
    tmp_path: Path,
    field: str,
) -> None:
    kwargs: dict[str, Any] = {field: 1}
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
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
        lease_id="lease-pytest-isolation-bool",
        max_repeated_action=3,
    )
    state = AgentRunState(objective="bounds", workspace=str(workspace))
    state_store = StateStore(run_dir / "state.json")
    state_store.save(state)

    with pytest.raises(ValueError, match=field):
        LiveRuntimeServices(
            workspace=workspace,
            state=state,
            evidence=cast(Any, object()),
            policy=cast(Any, object()),
            test_runner=cast(Any, FakeTestRunner()),
            max_tool_calls=10,
            max_repeated_action=3,
            state_store=state_store,
            workspace_root_identity=pin_directory_identity(workspace, label="test workspace"),
            control=control,
            **kwargs,
        )


def test_live_runtime_requires_lease_bound_workspace_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "run"
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
        lease_id="lease-missing-workspace-identity",
        max_repeated_action=3,
    )
    state = AgentRunState(objective="bounds", workspace=str(workspace))
    state_store = StateStore(run_dir / "state.json")
    state_store.save(state)

    with pytest.raises(ValueError, match="lease-bound workspace_root_identity"):
        LiveRuntimeServices(
            workspace=workspace,
            state=state,
            evidence=cast(Any, object()),
            policy=cast(Any, object()),
            test_runner=cast(Any, FakeTestRunner()),
            max_tool_calls=10,
            max_repeated_action=3,
            state_store=state_store,
            control=control,
        )
