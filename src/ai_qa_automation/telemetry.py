from __future__ import annotations

import json
import logging
import math
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any

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
    # Logging/rendering is observational only; handler, exporter, or hostile
    # object rendering failure must not alter deterministic runtime truth.
    with suppress(Exception):
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            **sanitize(fields),
        }
        logger.info(json.dumps(payload, sort_keys=True, default=str))


def get_tracer(name: str = _INSTRUMENTATION_SCOPE) -> Any:
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except Exception:
        # Provider/bootstrap failures are observational failures, not QA failures.
        return None


@contextmanager
def trace_span(name: str) -> Iterator[Any | None]:
    """Use OpenTelemetry without allowing tracing failure to alter runtime truth."""
    try:
        tracer = get_tracer()
    except Exception:
        tracer = None
    if tracer is None:
        yield None
        return
    try:
        span_context = tracer.start_as_current_span(name)
        span = span_context.__enter__()
    except Exception:
        yield None
        return

    try:
        yield span
    except BaseException as body_error:
        with suppress(Exception):
            span_context.__exit__(type(body_error), body_error, body_error.__traceback__)
        # Telemetry may never suppress or replace the application/runtime exception.
        raise
    else:
        # Span/exporter shutdown failure is observational only.
        with suppress(Exception):
            span_context.__exit__(None, None, None)


def get_meter(name: str = _INSTRUMENTATION_SCOPE) -> Any:
    """Return the global OpenTelemetry meter when the optional API is usable."""
    try:
        from opentelemetry import metrics

        return metrics.get_meter(name)
    except Exception:
        return None


@lru_cache(maxsize=1)
def _metric_instruments() -> dict[str, Any] | None:
    """Create reusable instruments once; exporter/provider configuration stays deployment-owned."""
    try:
        meter = get_meter()
        if meter is None:
            return None
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


def _instruments_or_none() -> dict[str, Any] | None:
    """Defensively isolate public metric helpers from provider/bootstrap failures."""
    try:
        return _metric_instruments()
    except Exception:
        return None


def _finite_non_negative(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except Exception:
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return number


def _safe_text(value: object, *, default: str) -> str:
    try:
        return str(value)
    except Exception:
        return default


def _safe_terminal_outcome(value: object) -> str:
    raw = "NOT_VERIFIED" if value is None else value
    normalized = _safe_text(raw, default="NOT_VERIFIED").upper()
    return normalized if normalized in _TERMINAL_OUTCOMES else "NOT_VERIFIED"


def _tool_surface(tool_name: object) -> str:
    name = _safe_text(tool_name, default="")
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
    terminal_status: object,
    duration_seconds: object = None,
    tool_calls: object = None,
) -> None:
    """Record one terminal run without high-cardinality identifiers or sensitive attributes."""
    try:
        instruments = _instruments_or_none()
        if instruments is None:
            return
        outcome = _safe_terminal_outcome(terminal_status)
        attributes = {"terminal.status": outcome}
        _safe_add(instruments["runs"], 1, attributes)

        for instrument_name, raw_value in {
            "duration": duration_seconds,
            "tool_calls": tool_calls,
        }.items():
            value = _finite_non_negative(raw_value)
            if value is not None:
                _safe_record(instruments[instrument_name], value, attributes)
    except Exception:
        return


def record_tool_event(tool_name: object, outcome: object) -> None:
    """Record coarse tool-surface lifecycle telemetry without arguments, paths, or payloads."""
    try:
        instruments = _instruments_or_none()
        normalized_outcome = _safe_text(outcome, default="").lower()
        if instruments is None or normalized_outcome not in _TOOL_OUTCOMES:
            return
        _safe_add(
            instruments["tool_events"],
            1,
            {"tool.surface": _tool_surface(tool_name), "tool.outcome": normalized_outcome},
        )
    except Exception:
        return


def record_policy_denial(category: object) -> None:
    """Record a bounded denial category; raw policy reasons stay in sanitized logs/journals."""
    try:
        instruments = _instruments_or_none()
        if instruments is None:
            return
        normalized = _safe_text(category, default="other").lower()
        if normalized not in _POLICY_CATEGORIES:
            normalized = "other"
        _safe_add(instruments["policy_denials"], 1, {"policy.category": normalized})
    except Exception:
        return


def record_mcp_outcome(provider: object, outcome: object) -> None:
    """Record normalized outcomes only for the two approved external provider families."""
    try:
        instruments = _instruments_or_none()
        if instruments is None:
            return
        normalized_provider = _safe_text(provider, default="other").lower()
        normalized_outcome = _safe_text(outcome, default="FAILED").upper()
        if normalized_provider not in _MCP_PROVIDERS:
            normalized_provider = "other"
        if normalized_outcome not in _MCP_OUTCOMES:
            normalized_outcome = "FAILED"
        _safe_add(
            instruments["mcp_outcomes"],
            1,
            {"mcp.provider": normalized_provider, "mcp.outcome": normalized_outcome},
        )
    except Exception:
        return
