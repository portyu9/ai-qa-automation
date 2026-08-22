from __future__ import annotations

import json
import logging
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Iterator

from .redaction import sanitize


def configure_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(message)s")


def emit_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event": event,
        **sanitize(fields),
    }
    logger.info(json.dumps(payload, sort_keys=True, default=str))


def get_tracer(name: str = "ai_qa_automation") -> Any:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    return trace.get_tracer(name)


@contextmanager
def trace_span(name: str) -> Iterator[Any | None]:
    """Use OpenTelemetry when installed without making it a runtime requirement."""
    tracer = get_tracer()
    if tracer is None:
        yield None
        return
    with tracer.start_as_current_span(name) as span:
        yield span
