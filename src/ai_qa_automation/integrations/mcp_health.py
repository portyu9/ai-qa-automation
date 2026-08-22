from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ..models import MCPStatus


def _mentions_http_status(rendered: str, code: int) -> bool:
    """Recognize status-shaped text without treating arbitrary business IDs as HTTP codes."""
    return bool(
        re.search(
            rf"\b(?:http(?:\s+status)?|status(?:\s+code)?|response\s+status(?:\s+code)?)"
            rf"\s*[:=]?\s*{code}\b",
            rendered,
        )
    )


def normalize_mcp_failure(
    *,
    status_code: int | None = None,
    error: BaseException | None = None,
    payload: Any = None,
    message: str | None = None,
) -> MCPStatus:
    """Normalize transport/auth/response failures without inventing remote state."""
    rendered = (message or (str(error) if error is not None else "")).lower()
    if (
        status_code in {401, 403}
        or isinstance(error, PermissionError)
        or any(token in rendered for token in ("unauthorized", "forbidden"))
        or any(_mentions_http_status(rendered, code) for code in (401, 403))
    ):
        return MCPStatus.UNAUTHORIZED
    if (
        status_code == 429
        or "rate limit" in rendered
        or "too many requests" in rendered
        or _mentions_http_status(rendered, 429)
    ):
        return MCPStatus.RATE_LIMITED
    if status_code is not None and status_code >= 500:
        return MCPStatus.UNAVAILABLE
    if isinstance(error, (TimeoutError, ConnectionError)) or any(
        token in rendered
        for token in (
            "timeout",
            "timed out",
            "connection refused",
            "connection reset",
            "unavailable",
        )
    ):
        return MCPStatus.UNAVAILABLE
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError, TypeError)):
        return MCPStatus.INVALID_RESPONSE
    if payload is not None and not isinstance(payload, (Mapping, list)):
        return MCPStatus.INVALID_RESPONSE
    return MCPStatus.FAILED
