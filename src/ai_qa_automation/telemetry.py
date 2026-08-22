from __future__ import annotations

import json
import logging
import math
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Iterator

from .redaction import sanitize

_INSTRUMENTATION_SCOPE = "ai_qa_automation"
_TERMINAL_OUTCOMES = {
    "SUCCESS",
    "FAILURE",
    "BLOCKED",
    "INSUFFICIENT_EVIDENCE",
    "POLICY_DENIED",
    "INFRASTRUCTURE_FAILURE",
    "CANCELLED",
    "BUDGET_EXCEEDED",
    "NOT_VERIFIED",
}
_MCP_PROVIDERS = {"github", "atlassian"}
_MCP_OUTCOMES = {
    "AVAILABLE",
    "NOT_CONFIGURED",
    "UNAUTHORIZED",
    "RATE_LIMITED",
    "UNAVAILABLE",
    "INVALID_RESPONSE",
    "FAILED",
}
_TOOL_OUTCOMES = {"requested", "allowed", "denied", "succeeded", "failed"}
_POLICY_CATEGORIES = {
    "runtime_budget",
    "runtime_circuit",
    "workspace_integrity",
    "mutation_transaction",
    "deterministic_policy",
    "other",
}


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(message)s")


def emit_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        **sanitize(fields),
    }
    logger.info(json.dumps(payload, sort_keys=True, default=str))


def get_tracer(name: str = _INSTRUMENTATION_SCOPE) -> Any:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace.get_tracer(name)


@contextmanager
def trace_span(name: str) -> Iterator[Any | None]:
    """Use OpenTelemetry tracing when installed without making it a runtime requirement."""
    tracer = get_tracer()
    if tracer is None:
        yield None
        return
    with tracer.start_as_current_span(name) as span:
        yield span


def get_meter(name: str = _INSTRUMENTATION_SCOPE) -> Any:
    """Return the global OpenTelemetry meter when the optional API is installed."""
    try:
        from opentelemetry import metrics
    except ImportError:
        return None
    return metrics.get_meter(name)


@lru_cache(maxsize=1)
def _metric_instruments() -> dict[str, Any] | None:
    """Create reusable instruments once; exporter/provider configuration stays deployment-owned."""
    meter = get_meter()
    if meter is None:
        return None
    try:
        return {
            "runs": meter.create_counter(
                "ai_qa.agent.runs",
                unit="1",
                description="Completed AI QA agent runs by deterministic terminal outcome.",
            ),
            "duration": meter.create_histogram(
                "ai_qa.agent.duration",
                unit="s",
                description="Wall-clock duration of completed AI QA agent runs.",
            ),
            "tool_calls": meter.create_histogram(
                "ai_qa.agent.tool_calls",
                unit="{call}",
                description="Controlled tool calls recorded per completed agent run.",
            ),
            "iterations": meter.create_histogram(
                "ai_qa.agent.iterations",
                unit="{iteration}",
                description="Agent response iterations recorded per completed run.",
            ),
            "tokens": meter.create_histogram(
                "ai_qa.agent.tokens",
                unit="{token}",
                description="Provider-reported input plus output tokens per completed run.",
            ),
            "cost": meter.create_histogram(
                "ai_qa.agent.cost",
                unit="USD",
                description="Provider-reported model cost in USD per completed run.",
            ),
            "tool_events": meter.create_counter(
                "ai_qa.tool.events",
                unit="1",
                description="Controlled tool lifecycle events grouped by bounded tool surface and outcome.",
            ),
            "policy_denials": meter.create_counter(
                "ai_qa.policy.denials",
                unit="1",
                description="Fail-closed runtime and deterministic-policy denials by coarse category.",
            ),
            "mcp_outcomes": meter.create_counter(
                "ai_qa.mcp.outcomes",
                unit="1",
                description="Observed approved-provider MCP outcomes by provider and normalized outcome.",
            ),
        }
    except Exception:
        # Telemetry is evidence-adjacent instrumentation, never execution authority.
        # A broken SDK/provider/exporter must not change the QA outcome.
        return None


def _finite_non_negative(value: int | float) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _safe_terminal_outcome(value: str | None) -> str:
    normalized = str(value or "NOT_VERIFIED").upper()
    return normalized if normalized in _TERMINAL_OUTCOMES else "NOT_VERIFIED"


def _tool_surface(tool_name: str) -> str:
    name = str(tool_name)
    if name.startswith("mcp__qa__"):
        return "internal_qa"
    if name.startswith("mcp__github__"):
        return "github_mcp"
    if name.startswith("mcp__atlassian__"):
        return "atlassian_mcp"
    return "other"


def _safe_add(instrument: Any, value: int | float, attributes: dict[str, str]) -> None:
    try:
        instrument.add(value, attributes)
    except Exception:
        return


def _safe_record(instrument: Any, value: int | float, attributes: dict[str, str]) -> None:
    try:
        instrument.record(value, attributes)
    except Exception:
        return


def record_run_metrics(
    *,
    terminal_status: str | None,
    duration_seconds: float,
    tool_calls: int,
    iterations: int,
    token_usage: int,
    cost_usd: float,
) -> None:
    """Record one run without high-cardinality identifiers or sensitive attributes."""
    instruments = _metric_instruments()
    if instruments is None:
        return
    outcome = _safe_terminal_outcome(terminal_status)
    attributes = {"terminal.status": outcome}
    _safe_add(instruments["runs"], 1, attributes)

    measurements = {
        "duration": duration_seconds,
        "tool_calls": tool_calls,
        "iterations": iterations,
        "tokens": token_usage,
        "cost": cost_usd,
    }
    for instrument_name, raw_value in measurements.items():
        value = _finite_non_negative(raw_value)
        if value is not None:
            _safe_record(instruments[instrument_name], value, attributes)


def record_tool_event(tool_name: str, outcome: str) -> None:
    """Record coarse tool-surface lifecycle telemetry without arguments, paths, or payloads."""
    instruments = _metric_instruments()
    normalized_outcome = str(outcome).lower()
    if instruments is None or normalized_outcome not in _TOOL_OUTCOMES:
        return
    _safe_add(
        instruments["tool_events"],
        1,
        {"tool.surface": _tool_surface(tool_name), "tool.outcome": normalized_outcome},
    )


def record_policy_denial(category: str) -> None:
    """Record a bounded denial category; raw policy reasons stay in sanitized logs/journals."""
    instruments = _metric_instruments()
    if instruments is None:
        return
    normalized = str(category).lower()
    if normalized not in _POLICY_CATEGORIES:
        normalized = "other"
    _safe_add(instruments["policy_denials"], 1, {"policy.category": normalized})


def record_mcp_outcome(provider: str, outcome: str) -> None:
    """Record normalized outcomes only for the two approved external provider families."""
    instruments = _metric_instruments()
    if instruments is None:
        return
    normalized_provider = str(provider).lower()
    normalized_outcome = str(outcome).upper()
    if normalized_provider not in _MCP_PROVIDERS:
        normalized_provider = "other"
    if normalized_outcome not in _MCP_OUTCOMES:
        normalized_outcome = "FAILED"
    _safe_add(
        instruments["mcp_outcomes"],
        1,
        {"mcp.provider": normalized_provider, "mcp.outcome": normalized_outcome},
    )
