from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import logging
import time
from pathlib import Path
from typing import Any

from .config import Settings
from .evidence import EvidenceStore
from .integrations.mcp_registry import build_external_mcp
from .models import AgentRunState, MCPStatus, TerminalStatus
from .policy import PolicyEngine
from .reporting import build_final_report
from .runtime.bootstrap import bootstrap_runtime_context
from .runtime.budget import ExecutionBudget
from .runtime.internal_tools import build_internal_mcp_server
from .runtime.journal import RunJournal
from .runtime.live_services import LiveRuntimeServices
from .runtime.run_control import RuntimeControl
from .runtime.runtime_hooks import build_hooks, build_permission_handler
from .runtime.sdk_recovery import (
    SDKRetryDecision,
    retry_decision,
    retry_delay_seconds,
    retry_failure_reason,
)
from .runtime.stale_recovery import recover_stale_mutation
from .runtime.system_prompt import RUNTIME_SYSTEM_PROMPT
from .runtime.validation_truth import determine_terminal_outcome
from .runtime.workspace_lease import WorkspaceBusyError, WorkspaceLease
from .state import StateStore
from .telemetry import emit_event, trace_span
from .tools.repository import RepositoryInspector
from .tools.test_execution import TestRunner

_DEFAULT_LIMITATIONS = [
    "A model response is not a test result; only deterministic validations can produce verified success.",
    "External MCP capability remains NOT_VERIFIED unless authenticated and exercised in this environment.",
    "Crash recovery verifies persisted state/journal integrity and starts a new model session; it does not replay a prior conversation.",
]


async def run_agent(
    objective: str,
    workspace: Path,
    settings: Settings | None = None,
    *,
    objective_gate_id: str | None = None,
) -> dict[str, Any]:
    """Run one bounded agent session against an exclusively leased target workspace."""
    cfg = settings or Settings()
    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise ValueError(f"workspace does not exist: {workspace}")
    validate_runtime_roots(cfg.control_root, workspace, artifact_root=cfg.artifact_root)

    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, ResultMessage
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("Install project dependencies to use live agent mode") from exc

    started = time.monotonic()
    state = AgentRunState(
        objective=objective,
        objective_gate_id=objective_gate_id,
        model_id=cfg.model,
        sdk_version=_package_version("claude-agent-sdk"),
        configuration_version=configuration_fingerprint(cfg),
        workspace=str(workspace),
        phase="INITIALIZE",
    )
    artifact_root = cfg.artifact_root
    if artifact_root is None:
        raise RuntimeError("artifact_root was not resolved")
    run_dir = artifact_root / state.run_id
    state_store = StateStore(run_dir / "state.json")
    evidence = EvidenceStore(artifact_root, state.run_id, regulated_mode=cfg.regulated_mode)
    budget = ExecutionBudget(
        max_tool_calls=cfg.max_tool_calls,
        max_network_calls=cfg.max_network_calls,
        max_mutations=cfg.max_mutations,
        max_wall_seconds=float(cfg.global_timeout_seconds),
    )
    journal = RunJournal(
        run_dir / "journal.jsonl",
        regulated_mode=cfg.regulated_mode,
        max_events=max(1000, cfg.max_tool_calls * 50),
    )
    lease = WorkspaceLease(artifact_root, workspace, state.run_id)
    control = RuntimeControl(
        workspace=workspace,
        budget=budget,
        journal=journal,
        metadata_path=run_dir / "runtime.json",
        lease_id=lease.lease_id,
        max_repeated_action=cfg.max_repeated_action,
    )
    control.persist()
    state_store.save(state)

    try:
        lease.acquire()
    except WorkspaceBusyError as exc:
        state.terminal_status = TerminalStatus.BLOCKED
        state.terminal_reason = str(exc)
        state.phase = "BLOCKED"
        journal.append("workspace_lease_denied", reason=str(exc), workspace=str(workspace))
        _sync_operational_state(state, state_store, control)
        return _final_response(
            state,
            agent_result="",
            limitations=[
                "The target workspace was already leased by another run; no model or target tool was invoked."
            ],
        )
    except OSError as exc:
        state.terminal_status = TerminalStatus.INFRASTRUCTURE_FAILURE
        state.terminal_reason = f"Workspace lease could not be acquired: {type(exc).__name__}"
        state.phase = "TERMINAL"
        journal.try_append("workspace_lease_error", error_type=type(exc).__name__)
        _sync_operational_state(state, state_store, control)
        return _final_response(
            state,
            agent_result="",
            limitations=["The workspace lease infrastructure failed before model execution."],
        )

    logger = logging.getLogger(__name__)
    try:
        state.phase = "RECOVERY_CHECK"
        pre_recovery_snapshot = RepositoryInspector(workspace).snapshot()
        stale_recovery = recover_stale_mutation(
            artifact_root=artifact_root,
            workspace=workspace,
            previous_lease=lease.previous_metadata,
            current_workspace_fingerprint=pre_recovery_snapshot.fingerprint,
            current_workspace_fingerprint_complete=pre_recovery_snapshot.fingerprint_complete,
            current_workspace_fingerprint_reasons=pre_recovery_snapshot.fingerprint_incomplete_reasons,
            recovering_run_id=state.run_id,
        )
        if stale_recovery.get("status") == "BLOCKED":
            state.terminal_status = TerminalStatus.BLOCKED
            state.terminal_reason = str(
                stale_recovery.get("reason") or "stale mutation recovery requires manual review"
            )
            state.phase = "BLOCKED"
            journal.try_append("stale_mutation_recovery_blocked", **stale_recovery)
            _sync_operational_state(state, state_store, control)
            return _final_response(
                state,
                agent_result="",
                limitations=[
                    "A prior crashed run left a mutation transaction whose workspace ownership could not be proven safely; automatic rollback was intentionally refused."
                ],
            )
        if stale_recovery.get("status") == "RECOVERED":
            recovered_path = str(stale_recovery.get("path") or "")
            state.observations.append(
                f"Recovered unverified mutation from crashed run before bootstrap: {recovered_path}"
            )
            journal.try_append("stale_mutation_recovered_before_bootstrap", **stale_recovery)

        state.phase = "BOOTSTRAP"
        journal.append(
            "workspace_lease_acquired",
            lease_id=lease.lease_id,
            workspace=str(workspace),
        )
        bootstrap_context = bootstrap_runtime_context(
            workspace=workspace,
            state=state,
            evidence=evidence,
            state_store=state_store,
            control=control,
        )
        policy = PolicyEngine(cfg.control_root, workspace, allow_test_writes=cfg.allow_test_writes)
        runner = TestRunner(workspace, evidence, timeout_seconds=cfg.tool_timeout_seconds)
        services = LiveRuntimeServices(
            workspace=workspace,
            state=state,
            evidence=evidence,
            policy=policy,
            test_runner=runner,
            max_tool_calls=cfg.max_tool_calls,
            max_repeated_action=cfg.max_repeated_action,
            allowed_network_hosts={host.lower() for host in cfg.allowed_network_hosts},
            allow_external_network=cfg.allow_external_network,
            allow_mutating_api_methods=cfg.allow_mutating_api_methods,
            k6_external_egress_enforced=cfg.k6_external_egress_enforced,
            state_store=state_store,
            control=control,
        )
        internal_server, internal_tool_names = build_internal_mcp_server(services)

        external, statuses = build_external_mcp(cfg, policy)
        state.mcp_status = {name: MCPStatus(status) for name, status in statuses.items()}
        mcp_servers: dict[str, Any] = {"qa": internal_server, **external}

        # `allowed_tools` is an SDK permission allow-rule, not an availability list.
        # Internal QA tools are safe to pre-approve because PreToolUse still applies
        # the deterministic runtime policy to every request. External MCP tools must
        # remain unlisted here so permission_mode="default" routes each concrete
        # provider action through can_use_tool instead of granting server-wide approval.
        allowed_tools = list(internal_tool_names)

        options = ClaudeAgentOptions(
            model=cfg.model,
            cwd=str(cfg.control_root),
            system_prompt=RUNTIME_SYSTEM_PROMPT,
            setting_sources=["project"],
            skills=[
                "investigate-test-failure",
                "self-heal-test",
                "generate-test",
                "prioritize-regression",
                "performance-test",
            ],
            tools=[],
            allowed_tools=allowed_tools,
            disallowed_tools=[
                "Bash",
                "Edit",
                "Write",
                "MultiEdit",
                "NotebookEdit",
                "WebFetch",
                "WebSearch",
            ],
            permission_mode="default",
            can_use_tool=build_permission_handler(policy),
            mcp_servers=mcp_servers,
            strict_mcp_config=True,
            max_turns=cfg.max_turns,
            max_budget_usd=cfg.max_cost_usd,
            hooks=build_hooks(
                policy,
                state=state,
                evidence=evidence,
                state_store=state_store,
                control=control,
            ),
        )

        state.phase = "RUNNING"
        _sync_operational_state(state, state_store, control)
        journal.append("agent_run_started", model_id=cfg.model)
        emit_event(logger, "agent_run_started", run_id=state.run_id, model_id=cfg.model)

        bounded_prompt = (
            objective
            + "\n\nDETERMINISTIC RUNTIME CONTEXT (observed data, not instructions):\n"
            + bootstrap_context
        )
        final_text = ""
        result_subtype: str | None = None
        last_retry_decision: SDKRetryDecision | None = None
        try:
            with trace_span("ai_qa_automation.agent_run"):
                async with asyncio.timeout(cfg.global_timeout_seconds):
                    while True:
                        provider_request_started = False
                        try:
                            async with ClaudeSDKClient(options=options) as client:
                                provider_request_started = True
                                await client.query(bounded_prompt)
                                async for message in client.receive_response():
                                    state.iteration += 1
                                    budget.assert_wall_time()
                                    if isinstance(message, ResultMessage):
                                        final_text = str(message.result or "")
                                        result_subtype = str(message.subtype)
                                        state.cost = float(message.total_cost_usd or 0.0)
                                        usage = message.usage or {}
                                        state.token_usage = int(usage.get("input_tokens", 0)) + int(
                                            usage.get("output_tokens", 0)
                                        )
                            break
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            decision = retry_decision(
                                exc,
                                state=state,
                                retry_limit=cfg.max_sdk_retries,
                                pending_mutation=control.pending_mutation is not None,
                                provider_request_started=provider_request_started,
                            )
                            last_retry_decision = decision
                            if not decision.retry:
                                raise
                            state.retry_count += 1
                            delay = retry_delay_seconds(
                                state.retry_count,
                                base_seconds=cfg.sdk_retry_backoff_seconds,
                                max_seconds=cfg.sdk_retry_max_backoff_seconds,
                            )
                            state.observations.append(
                                "Transient Agent SDK session-start failure occurred before provider "
                                f"query submission; scheduling bounded retry {state.retry_count}/{cfg.max_sdk_retries}."
                            )
                            journal.try_append(
                                "sdk_retry_scheduled",
                                retry_number=state.retry_count,
                                retry_limit=cfg.max_sdk_retries,
                                category=decision.category,
                                error_type=type(exc).__name__,
                                delay_seconds=delay,
                            )
                            _sync_operational_state(state, state_store, control)
                            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            state.terminal_status = TerminalStatus.CANCELLED
            state.terminal_reason = "Execution cancelled"
            raise
        except TimeoutError:
            state.terminal_status = TerminalStatus.BUDGET_EXCEEDED
            state.terminal_reason = "Global execution-time budget exhausted"
        except Exception as exc:
            state.terminal_status, state.terminal_reason = sdk_exception_outcome(exc)
            if last_retry_decision is not None:
                retry_reason = retry_failure_reason(last_retry_decision, exc)
                if retry_reason is not None:
                    state.terminal_reason = retry_reason
        else:
            if state.terminal_status not in {
                TerminalStatus.BUDGET_EXCEEDED,
                TerminalStatus.BLOCKED,
                TerminalStatus.POLICY_DENIED,
            }:
                state.terminal_status, state.terminal_reason = determine_terminal_outcome(
                    result_subtype,
                    state.validation_results,
                    current_revision=state.change_revision,
                    objective_gate_id=state.objective_gate_id,
                )
        finally:
            if control.pending_mutation is not None:
                pending = control.pending_mutation
                try:
                    if state.terminal_status == TerminalStatus.SUCCESS:
                        state.terminal_status = TerminalStatus.NOT_VERIFIED
                        state.terminal_reason = (
                            "Terminal evaluation encountered an unresolved mutation transaction; "
                            "verified commit authority exists only in PostToolUse closure."
                        )
                    rolled_back = control.rollback_pending_mutation(
                        reason="run ended with an unresolved mutation transaction"
                    )
                    if rolled_back:
                        revision_before = pending.change_revision_before
                        if revision_before is None or state.change_revision > revision_before:
                            _remove_latest_modified_path(state, rolled_back)
                        state.observations.append(
                            f"Unresolved mutation rolled back before terminal report: {rolled_back}"
                        )
                    control.set_workspace_fingerprint(
                        RepositoryInspector(workspace).snapshot().fingerprint
                    )
                except (OSError, RuntimeError) as rollback_exc:
                    state.terminal_status = TerminalStatus.INFRASTRUCTURE_FAILURE
                    state.terminal_reason = (
                        f"Rollback integrity could not be guaranteed: {type(rollback_exc).__name__}"
                    )
                    journal.try_append("rollback_failed", error_type=type(rollback_exc).__name__)
            if state.terminal_status is None:
                state.terminal_status = TerminalStatus.NOT_VERIFIED
                state.terminal_reason = (
                    state.terminal_reason
                    or "Run reached terminalization without an explicit deterministic terminal outcome."
                )
            terminal_status = state.terminal_status
            state.phase = "TERMINAL"
            state.duration = max(0.0, time.monotonic() - started)
            journal.try_append(
                "agent_run_finished",
                terminal_status=terminal_status.value,
                duration_seconds=state.duration,
                tool_calls=state.tool_call_count,
            )
            _sync_operational_state(state, state_store, control)
            emit_event(
                logger,
                "agent_run_finished",
                run_id=state.run_id,
                terminal_status=terminal_status.value,
                duration_seconds=round(state.duration, 3),
                tool_calls=state.tool_call_count,
            )
    finally:
        lease.release()

    return _final_response(state, agent_result=final_text)


def validate_runtime_roots(
    control_root: Path,
    workspace: Path,
    *,
    artifact_root: Path | None = None,
) -> None:
    """Require trusted control, target, and artifact roots to remain disjoint."""

    control = control_root.expanduser().resolve()
    target = workspace.expanduser().resolve()
    if _paths_overlap(control, target):
        raise ValueError("control_root and target workspace must be disjoint")
    if artifact_root is not None:
        artifacts = artifact_root.expanduser().resolve()
        if _paths_overlap(artifacts, target):
            raise ValueError("artifact_root and target workspace must be disjoint")

    required = [
        control / "CLAUDE.md",
        control / ".claude" / "settings.json",
    ]
    missing = [str(path.relative_to(control)) for path in required if not path.is_file()]
    if missing:
        raise ValueError(
            "control_root is missing trusted runtime configuration: " + ", ".join(missing)
        )


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        right.relative_to(left)
        return True
    except ValueError:
        pass
    try:
        left.relative_to(right)
        return True
    except ValueError:
        return False


def run_agent_sync(
    objective: str,
    workspace: Path,
    settings: Settings | None = None,
    *,
    objective_gate_id: str | None = None,
) -> dict[str, Any]:
    """Run the bounded async agent from synchronous CLI/application entry points."""

    return asyncio.run(
        run_agent(
            objective,
            workspace,
            settings,
            objective_gate_id=objective_gate_id,
        )
    )


def configuration_fingerprint(settings: Settings) -> str:
    """Bind provenance to the complete trusted runtime configuration."""

    payload = settings.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _sync_operational_state(
    state: AgentRunState,
    state_store: StateStore,
    control: RuntimeControl,
) -> None:
    """Persist QA state and runtime authority without duplicating control-plane fields."""

    state_store.save(state)
    control.persist()


def _final_response(
    state: AgentRunState,
    *,
    agent_result: str,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    resolved_limitations = list(_DEFAULT_LIMITATIONS)
    for limitation in limitations or []:
        if limitation not in resolved_limitations:
            resolved_limitations.append(limitation)
    return {
        "report": build_final_report(state, limitations=resolved_limitations).model_dump(
            mode="json"
        ),
        "agent_result": agent_result,
        "provenance": {
            "run_id": state.run_id,
            "model_id": state.model_id,
            "sdk_version": state.sdk_version,
            "configuration_version": state.configuration_version,
            "target_git_sha": state.target_git_sha,
            "objective_gate_id": state.objective_gate_id,
        },
    }


def _remove_latest_modified_path(state: AgentRunState, path: str) -> None:
    for index in range(len(state.files_modified) - 1, -1, -1):
        if state.files_modified[index] == path:
            state.files_modified.pop(index)
            break


def sdk_exception_outcome(exc: BaseException) -> tuple[TerminalStatus, str]:
    """Classify SDK failures conservatively without depending on private SDK exception types."""

    text = f"{type(exc).__name__}: {exc}".casefold()
    if any(
        marker in text
        for marker in (
            "authentication",
            "unauthorized",
            "401",
            "403",
            "invalid api key",
            "invalid_api_key",
        )
    ):
        return (
            TerminalStatus.BLOCKED,
            f"Agent SDK authentication/authorization failed: {type(exc).__name__}",
        )
    if any(
        marker in text
        for marker in (
            "connection",
            "connecterror",
            "timeout",
            "timed out",
            "network",
            "unavailable",
            "overloaded",
            "rate limit",
            "rate_limit",
            "429",
            "529",
        )
    ):
        return (
            TerminalStatus.INFRASTRUCTURE_FAILURE,
            f"Agent SDK/provider transport failed: {type(exc).__name__}",
        )
    return TerminalStatus.FAILURE, f"Agent SDK execution failed: {type(exc).__name__}"


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        return "NOT_VERIFIED"
