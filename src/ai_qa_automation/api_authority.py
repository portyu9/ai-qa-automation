from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

SAFE_API_OBSERVATION_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATING_API_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_MAX_API_URL_CHARS = 8_192
_MAX_API_QUERY_FIELDS = 64
_MAX_URL_DECODE_ROUNDS = 4
_ACTION_QUERY_KEYS = frozenset({"action", "op", "operation", "command", "cmd", "do", "method"})
_ACTION_TOKENS = frozenset(
    {
        "add",
        "apply",
        "approve",
        "assign",
        "cancel",
        "close",
        "commit",
        "create",
        "delete",
        "deploy",
        "destroy",
        "disable",
        "edit",
        "enable",
        "execute",
        "merge",
        "mutate",
        "publish",
        "purge",
        "remove",
        "reopen",
        "reset",
        "restart",
        "revoke",
        "rotate",
        "run",
        "set",
        "start",
        "stop",
        "transition",
        "trigger",
        "update",
        "write",
    }
)
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class ApiObservationAuthority:
    """Deterministic classification for the generic HTTP observation primitive."""

    normalized_method: str
    allowed: bool
    code: str | None = None
    reason: str | None = None


def classify_api_observation_method(method: str) -> ApiObservationAuthority:
    normalized = str(method).upper().strip()
    if normalized in SAFE_API_OBSERVATION_METHODS:
        return ApiObservationAuthority(normalized_method=normalized, allowed=True)
    if normalized in MUTATING_API_METHODS:
        return ApiObservationAuthority(
            normalized_method=normalized,
            allowed=False,
            code="mutating_method",
            reason=(
                "Generic API observation cannot submit mutating HTTP methods; "
                "remote mutation requires a separately typed operation with reversible "
                "side-effect authority."
            ),
        )
    return ApiObservationAuthority(
        normalized_method=normalized,
        allowed=False,
        code="unsupported_method",
        reason="HTTP method is outside the read-only API observation allowlist.",
    )


def classify_api_observation_request(method: str, url: str) -> ApiObservationAuthority:
    method_authority = classify_api_observation_method(method)
    if not method_authority.allowed:
        return method_authority

    raw_url = str(url)
    if len(raw_url) > _MAX_API_URL_CHARS:
        return ApiObservationAuthority(
            normalized_method=method_authority.normalized_method,
            allowed=False,
            code="url_bounds",
            reason=f"API observation URL exceeds the {_MAX_API_URL_CHARS}-character bound.",
        )
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return ApiObservationAuthority(
            normalized_method=method_authority.normalized_method,
            allowed=False,
            code="malformed_url",
            reason="API observation URL is malformed.",
        )
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        return ApiObservationAuthority(
            normalized_method=method_authority.normalized_method,
            allowed=False,
            code="malformed_url",
            reason="API observation requires an explicit HTTP(S) URL with a host.",
        )

    try:
        path_action = _contains_action_token(parsed.path)
    except ValueError:
        return _encoding_bound_denial(method_authority.normalized_method)
    if path_action:
        return ApiObservationAuthority(
            normalized_method=method_authority.normalized_method,
            allowed=False,
            code="action_semantics",
            reason=(
                "API observation URL path contains explicit action semantics; "
                "the generic observation primitive cannot authorize remote side effects."
            ),
        )

    try:
        query_items = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=_MAX_API_QUERY_FIELDS,
        )
    except ValueError:
        return ApiObservationAuthority(
            normalized_method=method_authority.normalized_method,
            allowed=False,
            code="query_bounds",
            reason=f"API observation query exceeds the {_MAX_API_QUERY_FIELDS}-field bound.",
        )

    for key, value in query_items:
        try:
            key_tokens = _decoded_tokens(key)
            value_tokens = _decoded_tokens(value)
        except ValueError:
            return _encoding_bound_denial(method_authority.normalized_method)
        if any(token in _ACTION_TOKENS for token in key_tokens):
            return ApiObservationAuthority(
                normalized_method=method_authority.normalized_method,
                allowed=False,
                code="action_semantics",
                reason=(
                    "API observation query contains explicit action semantics; "
                    "the generic observation primitive cannot authorize remote side effects."
                ),
            )
        if any(token in _ACTION_QUERY_KEYS for token in key_tokens) and any(
            token in _ACTION_TOKENS for token in value_tokens
        ):
            return ApiObservationAuthority(
                normalized_method=method_authority.normalized_method,
                allowed=False,
                code="action_semantics",
                reason=(
                    "API observation query contains explicit action semantics; "
                    "the generic observation primitive cannot authorize remote side effects."
                ),
            )

    return method_authority


def _encoding_bound_denial(normalized_method: str) -> ApiObservationAuthority:
    return ApiObservationAuthority(
        normalized_method=normalized_method,
        allowed=False,
        code="encoding_bounds",
        reason=(
            "API observation URL requires more decoding rounds than the deterministic "
            "classification bound permits."
        ),
    )


def _contains_action_token(value: str) -> bool:
    return any(token in _ACTION_TOKENS for token in _decoded_tokens(value))


def _decoded_tokens(value: str) -> tuple[str, ...]:
    decoded = str(value)
    for _ in range(_MAX_URL_DECODE_ROUNDS):
        next_value = unquote(decoded)
        if next_value == decoded:
            return tuple(_TOKEN_PATTERN.findall(decoded.casefold()))
        decoded = next_value
    if unquote(decoded) != decoded:
        raise ValueError("URL decoding did not converge inside the deterministic bound")
    return tuple(_TOKEN_PATTERN.findall(decoded.casefold()))
