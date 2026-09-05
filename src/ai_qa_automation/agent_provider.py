from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_support import _sync_operational_state
from .config import Settings
from .models import AgentRunState, ControlPlaneRevalidationStatus, TerminalStatus
from .runtime.budget import ExecutionBudget
from .runtime.control_plane_provenance import (
    ControlPlaneCapture,
    capture_control_plane_subject,
    same_control_plane_capture,
)
from .runtime.journal import RunJournal
from .runtime.run_control import RuntimeControl
from .runtime.sdk_recovery import (
    SDKRetryDecision,
    retry_decision,
    retry_delay_seconds,
)
from .runtime.sdk_result_bounds import SDKResultBoundsError, validate_sdk_result_message
from .state import StateStore


@dataclass(frozen=True)
class ProviderSessionOutcome:
    final_text: str
    result_subtype: str | None
    last_retry_decision: SDKRetryDecision | None
    pre_provider_denial: ControlPlaneRevalidationStatus | None
    failure: Exception | None = None


async def execute_sdk_sessions(
    *,
    client_type: Any,
    result_message_type: type[Any],
    options: Any,
    bounded_prompt: str,
    state: AgentRunState,
    budget: ExecutionBudget,
    control: RuntimeControl,
    cfg: Settings,
    state_store: StateStore,
    journal: RunJournal,
    control_plane_capture: ControlPlaneCapture,
) -> ProviderSessionOutcome:
    """Execute bounded SDK sessions with exact control-plane admission before each attempt."""

    final_text = ""
    result_subtype: str | None = None
    result_message_seen = False
    last_retry_decision: SDKRetryDecision | None = None
    pre_provider_denial: ControlPlaneRevalidationStatus | None = None
    while True:
        provider_request_started = False
        (
            pre_provider_status,
            pre_provider_digest,
            pre_provider_reason,
        ) = _revalidate_control_plane_before_provider(
            control_plane_capture,
            cfg.control_root,
        )
        journal.try_append(
            "pre_provider_control_plane_revalidation",
            status=pre_provider_status.value,
            reason=pre_provider_reason,
            bound_subject_digest=control_plane_capture.subject.subject_digest,
            observed_subject_digest=pre_provider_digest,
        )
        if pre_provider_status is not ControlPlaneRevalidationStatus.VERIFIED:
            pre_provider_denial = pre_provider_status
            state.control_plane_revalidation_status = pre_provider_status
            state.control_plane_terminal_subject_digest = pre_provider_digest
            if pre_provider_status is ControlPlaneRevalidationStatus.UNAVAILABLE:
                state.terminal_status = TerminalStatus.INFRASTRUCTURE_FAILURE
                state.terminal_reason = (
                    "Provider execution was refused because trusted control-plane "
                    "identity could not be revalidated safely immediately before "
                    "the SDK session."
                )
            else:
                state.terminal_status = TerminalStatus.BLOCKED
                state.terminal_reason = (
                    "Provider execution was refused because the trusted control-plane "
                    "subject drifted after run-start provenance was bound."
                )
            _sync_operational_state(state, state_store, control)
            return ProviderSessionOutcome(
                final_text=final_text,
                result_subtype=result_subtype,
                last_retry_decision=last_retry_decision,
                pre_provider_denial=pre_provider_denial,
            )
        try:
            async with client_type(options=options) as client:
                provider_request_started = True
                await client.query(bounded_prompt)
                async for message in client.receive_response():
                    state.iteration += 1
                    budget.assert_wall_time()
                    if isinstance(message, result_message_type):
                        if result_message_seen:
                            raise SDKResultBoundsError(
                                "duplicate_result_message",
                                "Agent SDK emitted more than one terminal result message",
                            )
                        bounded_result = validate_sdk_result_message(
                            message,
                            max_cost_usd=cfg.max_cost_usd,
                        )
                        result_message_seen = True
                        final_text = bounded_result.result
                        result_subtype = bounded_result.subtype
                        state.cost = bounded_result.total_cost_usd
                        state.token_usage = bounded_result.token_usage
                        if bounded_result.budget_exceeded:
                            state.terminal_status = TerminalStatus.BUDGET_EXCEEDED
                            state.terminal_reason = (
                                "Agent SDK reported cost above the configured runtime budget"
                            )
            if not result_message_seen:
                return ProviderSessionOutcome(
                    final_text=final_text,
                    result_subtype=result_subtype,
                    last_retry_decision=last_retry_decision,
                    pre_provider_denial=pre_provider_denial,
                    failure=SDKResultBoundsError(
                        "missing_result_message",
                        "Agent SDK response ended without a terminal result message",
                    ),
                )
            return ProviderSessionOutcome(
                final_text=final_text,
                result_subtype=result_subtype,
                last_retry_decision=last_retry_decision,
                pre_provider_denial=pre_provider_denial,
            )
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
                return ProviderSessionOutcome(
                    final_text=final_text,
                    result_subtype=result_subtype,
                    last_retry_decision=last_retry_decision,
                    pre_provider_denial=pre_provider_denial,
                    failure=exc,
                )
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


def _revalidate_control_plane_before_provider(
    bound: ControlPlaneCapture,
    control_root: Path,
) -> tuple[ControlPlaneRevalidationStatus, str | None, str]:
    """Require the exact bound controller bytes immediately before each SDK session."""

    try:
        current = capture_control_plane_subject(control_root)
    except (OSError, RuntimeError, ValueError) as exc:
        return (
            ControlPlaneRevalidationStatus.UNAVAILABLE,
            None,
            "trusted control-plane subject could not be revalidated safely before provider "
            f"execution: {type(exc).__name__}",
        )
    if same_control_plane_capture(bound, current):
        return (
            ControlPlaneRevalidationStatus.VERIFIED,
            current.subject.subject_digest,
            "trusted control-plane subject matches the bound run-start subject before provider "
            "execution",
        )
    content_matches = current.subject.subject_digest == bound.subject.subject_digest
    return (
        ControlPlaneRevalidationStatus.DRIFTED,
        current.subject.subject_digest,
        (
            "trusted control-plane content changed before provider execution"
            if not content_matches
            else "trusted control-plane filesystem ownership/metadata changed before provider "
            "execution"
        ),
    )
