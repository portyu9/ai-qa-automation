from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,\"']+"),
    re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)((?:api[_-]?key|token|password|secret|cookie|set-cookie)\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    re.compile(r"(?i)(https?://[^:/\s]+:)[^@/\s]+(@)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.S,
    ),
]
_SENSITIVE_KEYS = re.compile(
    r"(?i)(authorization|api[_-]?key|token|password|secret|cookie|private[_-]?key)"
)
_NETWORK_URL_PATTERN = re.compile(r"(?i)\b(?:https?|wss?)://[^\s<>\"']+")
_OPAQUE_URL_PATTERN = re.compile(r"(?i)\b(?:data|blob):[^\s<>\"']+")
_TRAILING_URL_PUNCTUATION = ".,;!?)"
_REDACTED_PATH_PATTERN = re.compile(r"^/_redacted_path_sha256/[0-9a-f]{64}$")


def _replacement(match: re.Match[str]) -> str:
    if match.lastindex == 2 and match.group(2) == "@":
        return f"{match.group(1)}[REDACTED]@"
    if match.lastindex:
        return f"{match.group(1)}[REDACTED]"
    return "[REDACTED]"


def _safe_path(path: str) -> str:
    if path in {"", "/"} or _REDACTED_PATH_PATTERN.fullmatch(path):
        return path
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return f"/_redacted_path_sha256/{digest}"


def _safe_network_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    trailing = ""
    while raw and raw[-1] in _TRAILING_URL_PUNCTUATION:
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if not host:
            return "[REDACTED_URL]" + trailing
        rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        port = parsed.port
    except ValueError:
        return "[REDACTED_URL]" + trailing
    netloc = rendered_host if port is None else f"{rendered_host}:{port}"
    safe = urlunsplit((parsed.scheme, netloc, _safe_path(parsed.path), "", ""))
    return safe + trailing


def _safe_opaque_url(match: re.Match[str]) -> str:
    raw = match.group(0)
    scheme = raw.split(":", 1)[0].casefold()
    return f"{scheme}:[REDACTED]"


def redact_text(value: str) -> str:
    redacted = _NETWORK_URL_PATTERN.sub(_safe_network_url, value)
    redacted = _OPAQUE_URL_PATTERN.sub(_safe_opaque_url, redacted)
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(_replacement, redacted)
    return redacted


def sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            rendered_key = str(key)
            result[rendered_key] = (
                "[REDACTED]" if _SENSITIVE_KEYS.search(rendered_key) else sanitize(item)
            )
        return result
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    if isinstance(value, tuple):
        return tuple(sanitize(v) for v in value)
    return value
