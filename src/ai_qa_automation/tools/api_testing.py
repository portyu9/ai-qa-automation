from __future__ import annotations

import asyncio
import hashlib
import math
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ..api_authority import (
    SAFE_API_OBSERVATION_METHODS,
    classify_api_observation_request,
)
from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind
from ..network_authority import AuthorizedNetworkHosts, authorize_network_url
from ..redaction import redact_text, sanitize
from ..runtime.tool_input_bounds import ToolInputBoundsError, bounded_json_loads

_MAX_API_RESPONSE_BYTES = 5_000_000
_MAX_API_TIMEOUT_SECONDS = 900
_MAX_API_RESPONSE_HEADERS = 200
_MAX_API_RESPONSE_HEADER_BYTES = 64_000
_MAX_API_REQUEST_HEADERS = 64
_MAX_API_REQUEST_HEADER_BYTES = 16_384
_API_RAW_CHUNK_BYTES = 64_000
_HTTP_HEADER_NAME_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_ALLOWED_OBSERVATION_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "authorization",
        "cache-control",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-unmodified-since",
        "range",
        "user-agent",
    }
)


class ApiProbeTransportError(RuntimeError):
    """Transport failure that retains the evidence record created for the attempt."""

    def __init__(self, message: str, evidence_id: str) -> None:
        super().__init__(message)
        self.evidence_id = evidence_id


class _ObservationBoundaryViolation(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ApiProbeResult:
    status_code: int | None
    body: Any
    headers: dict[str, str]
    elapsed_ms: float
    evidence_id: str
    truncated: bool | None = False
    json_parsed: bool = False
    utf8_valid: bool | None = None


def _utf8_bytes_bounded(value: str, *, remaining: int) -> int:
    total = 0
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise _ObservationBoundaryViolation(
                "header_unicode",
                "API response headers contain invalid Unicode",
            )
        if codepoint <= 0x7F:
            total += 1
        elif codepoint <= 0x7FF:
            total += 2
        elif codepoint <= 0xFFFF:
            total += 3
        else:
            total += 4
        if total > remaining:
            raise _ObservationBoundaryViolation(
                "header_bytes",
                "API response headers exceed the aggregate text bound",
            )
    return total


def _bounded_headers(headers: httpx.Headers) -> dict[str, str]:
    if len(headers) > _MAX_API_RESPONSE_HEADERS:
        raise _ObservationBoundaryViolation(
            "header_count",
            "API response exceeds the header-count bound",
        )

    raw_total = 0
    for raw_name, raw_value in headers.raw:
        raw_total += len(raw_name) + len(raw_value)
        if raw_total > _MAX_API_RESPONSE_HEADER_BYTES:
            raise _ObservationBoundaryViolation(
                "header_bytes",
                "API response headers exceed the aggregate text bound",
            )

    text_total = 0
    for text_name, text_value in headers.multi_items():
        text_total += _utf8_bytes_bounded(
            text_name, remaining=_MAX_API_RESPONSE_HEADER_BYTES - text_total
        )
        text_total += _utf8_bytes_bounded(
            text_value, remaining=_MAX_API_RESPONSE_HEADER_BYTES - text_total
        )

    sanitized = sanitize(dict(headers))
    if not isinstance(sanitized, dict):  # pragma: no cover - sanitize preserves mappings
        raise TypeError("sanitized API response headers must remain a mapping")

    result: dict[str, str] = {}
    output_total = 0
    for key, value in sanitized.items():
        rendered_key = str(key)
        rendered_value = str(value)
        output_total += _utf8_bytes_bounded(
            rendered_key, remaining=_MAX_API_RESPONSE_HEADER_BYTES - output_total
        )
        output_total += _utf8_bytes_bounded(
            rendered_value, remaining=_MAX_API_RESPONSE_HEADER_BYTES - output_total
        )
        result[rendered_key] = rendered_value
    return result


def _bounded_ascii_header_component(value: Any, *, remaining: int, label: str) -> bytes:
    if isinstance(value, bytes):
        encoded = value
    elif isinstance(value, str):
        if len(value) > remaining:
            raise PermissionError("API observation request headers exceed the aggregate byte bound")
        try:
            encoded = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PermissionError(f"API observation request {label} must be ASCII") from exc
    else:
        raise PermissionError(f"API observation request {label} must be text or bytes")
    if len(encoded) > remaining:
        raise PermissionError("API observation request headers exceed the aggregate byte bound")
    try:
        encoded.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PermissionError(f"API observation request {label} must be ASCII") from exc
    if label == "header name":
        if not _HTTP_HEADER_NAME_RE.fullmatch(encoded):
            raise PermissionError("API observation request header name is malformed")
    elif any(byte < 0x20 or byte == 0x7F for byte in encoded):
        raise PermissionError("API observation request header value contains control characters")
    return encoded


def _bounded_request_header_pairs(value: Any) -> list[tuple[bytes, bytes]]:
    """Ingest caller headers with limits before HTTPX may normalize/materialize them."""

    if value is None:
        return []
    if isinstance(value, httpx.Headers):
        source: Any = value.raw
    elif isinstance(value, Mapping):
        source = value.items()
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        source = value
    else:
        raise PermissionError(
            "API observation request headers must be a bounded mapping or sequence"
        )

    try:
        declared_count = len(value)
    except TypeError:
        declared_count = None
    if declared_count is not None and declared_count > _MAX_API_REQUEST_HEADERS:
        raise PermissionError(
            f"API observation request exceeds the {_MAX_API_REQUEST_HEADERS}-header bound"
        )

    pairs: list[tuple[bytes, bytes]] = []
    total = 0
    for index, item in enumerate(source):
        if index >= _MAX_API_REQUEST_HEADERS:
            raise PermissionError(
                f"API observation request exceeds the {_MAX_API_REQUEST_HEADERS}-header bound"
            )
        if not isinstance(item, Sequence) or isinstance(item, (str, bytes, bytearray)):
            raise PermissionError("API observation request header entries must be name/value pairs")
        if len(item) != 2:
            raise PermissionError("API observation request header entries must be name/value pairs")
        raw_name = _bounded_ascii_header_component(
            item[0],
            remaining=_MAX_API_REQUEST_HEADER_BYTES - total,
            label="header name",
        )
        total += len(raw_name)
        raw_value = _bounded_ascii_header_component(
            item[1],
            remaining=_MAX_API_REQUEST_HEADER_BYTES - total,
            label="header value",
        )
        total += len(raw_value)
        normalized_name = raw_name.decode("ascii").casefold()
        if normalized_name not in _ALLOWED_OBSERVATION_REQUEST_HEADERS:
            raise PermissionError(
                f"API observation request header is not authorized: {normalized_name}"
            )
        pairs.append((raw_name, raw_value))
    return pairs


def _observation_request_headers(value: Any) -> httpx.Headers:
    pairs = _bounded_request_header_pairs(value)
    headers = httpx.Headers(pairs)
    headers["Accept-Encoding"] = "identity"
    return headers


class ApiProbe:
    def __init__(
        self,
        evidence: EvidenceStore,
        *,
        allow_hosts: set[str] | None = None,
        allowed_methods: set[str] | None = None,
        timeout_seconds: float = 10,
        max_response_bytes: int = 100_000,
        external_egress_enforced: bool | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= _MAX_API_TIMEOUT_SECONDS
        ):
            raise ValueError(
                f"timeout_seconds must be a positive finite number no greater than {_MAX_API_TIMEOUT_SECONDS}"
            )
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1 <= max_response_bytes <= _MAX_API_RESPONSE_BYTES
        ):
            raise ValueError(
                f"max_response_bytes must be an integer between 1 and {_MAX_API_RESPONSE_BYTES}"
            )
        self.evidence = evidence
        inherited_egress = (
            allow_hosts.external_egress_enforced
            if isinstance(allow_hosts, AuthorizedNetworkHosts)
            else False
        )
        self.allow_hosts = {
            str(host).strip().lower() for host in (allow_hosts or set()) if str(host).strip()
        }
        configured_methods = (
            set(SAFE_API_OBSERVATION_METHODS) if allowed_methods is None else set(allowed_methods)
        )
        self.allowed_methods = {
            str(method).strip().upper() for method in configured_methods if str(method).strip()
        }
        if not self.allowed_methods:
            raise ValueError(
                "allowed_methods must contain at least one read-only observation method"
            )
        unsupported_methods = self.allowed_methods - SAFE_API_OBSERVATION_METHODS
        if unsupported_methods:
            rendered = ", ".join(sorted(unsupported_methods))
            raise ValueError(
                "ApiProbe is observation-only; allowed_methods cannot include mutating or "
                "unsupported "
                f"methods: {rendered}"
            )
        if external_egress_enforced is not None and not isinstance(external_egress_enforced, bool):
            raise ValueError("external_egress_enforced must be a boolean or None")
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.external_egress_enforced = (
            inherited_egress if external_egress_enforced is None else external_egress_enforced
        )
        self.transport = transport

    async def request(self, method: str, url: str, **kwargs: Any) -> ApiProbeResult:
        authority = classify_api_observation_request(method, url)
        normalized_method = authority.normalized_method
        if not authority.allowed:
            raise PermissionError(authority.reason or "API observation request is denied")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        authorize_network_url(
            url,
            allowed_hosts=self.allow_hosts,
            allow_external_network=True,
            external_egress_enforced=self.external_egress_enforced,
        )
        if normalized_method not in self.allowed_methods:
            raise PermissionError(
                f"HTTP method is not allowlisted for this probe: {normalized_method or '<missing>'}"
            )
        if kwargs.get("follow_redirects") not in (None, False):
            raise PermissionError("API probe redirects are disabled by adapter policy")
        kwargs.pop("follow_redirects", None)
        request_headers = _observation_request_headers(kwargs.pop("headers", None))
        if kwargs:
            modifiers = ", ".join(sorted(str(key) for key in kwargs))
            raise PermissionError(
                "API observation request modifiers are not authorized after URL classification: "
                f"{modifiers}"
            )

        started = time.monotonic()
        content = bytearray()
        truncated = False
        safe_url = redact_text(url)
        status_code: int | None = None
        headers: dict[str, str] = {}
        try:
            async with (
                asyncio.timeout(self.timeout_seconds),
                httpx.AsyncClient(
                    timeout=self.timeout_seconds,
                    follow_redirects=False,
                    transport=self.transport,
                    trust_env=False,
                ) as client,
                client.stream(
                    normalized_method,
                    url,
                    headers=request_headers,
                    follow_redirects=False,
                ) as response,
            ):
                status_code = response.status_code
                headers = _bounded_headers(response.headers)
                content_encoding = response.headers.get("content-encoding", "").strip().casefold()
                if content_encoding not in {"", "identity"}:
                    raise _ObservationBoundaryViolation(
                        "content_encoding",
                        "API response used a content encoding despite the identity-only request",
                    )
                chunk_size = min(_API_RAW_CHUNK_BYTES, self.max_response_bytes + 1)
                async for chunk in response.aiter_raw(chunk_size=chunk_size):
                    remaining = self.max_response_bytes - len(content)
                    if remaining <= 0:
                        truncated = True
                        break
                    content.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
        except (httpx.RequestError, TimeoutError) as exc:
            elapsed_ms = (time.monotonic() - started) * 1000
            error_message = (
                "API probe exceeded its total timeout budget"
                if isinstance(exc, TimeoutError)
                else redact_text(str(exc))
            )
            item = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.NETWORK_ERROR,
                    source="httpx",
                    source_identifier=f"{normalized_method} {safe_url}",
                    summary=f"HTTP transport failure contacting {host}",
                    structured_data={
                        "error_type": type(exc).__name__,
                        "error": error_message,
                        "elapsed_ms": elapsed_ms,
                    },
                )
            )
            raise ApiProbeTransportError(error_message, item.id) from exc
        except _ObservationBoundaryViolation as exc:
            elapsed_ms = (time.monotonic() - started) * 1000
            item = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.HTTP_RESPONSE,
                    source="httpx",
                    source_identifier=f"{normalized_method} {safe_url}",
                    summary=f"HTTP response observation rejected from {host}",
                    structured_data={
                        "status_code": status_code,
                        "observation_error": exc.code,
                        "response_body_observed": False,
                        "elapsed_ms": elapsed_ms,
                    },
                )
            )
            return ApiProbeResult(
                status_code=None,
                body=None,
                headers={},
                elapsed_ms=elapsed_ms,
                evidence_id=item.id,
                truncated=None,
                json_parsed=False,
                utf8_valid=None,
            )
        elapsed_ms = (time.monotonic() - started) * 1000
        if status_code is None:  # pragma: no cover - response context always sets it before success
            raise RuntimeError("API response status was not observed")

        raw_bytes = bytes(content)
        try:
            decoded = raw_bytes.decode("utf-8")
            utf8_valid = True
            raw_body: Any = decoded
        except UnicodeDecodeError:
            utf8_valid = False
            raw_body = (
                "<INVALID_UTF8_RESPONSE_BODY "
                f"bytes={len(raw_bytes)} sha256={hashlib.sha256(raw_bytes).hexdigest()}>"
            )

        json_parsed = False
        if not truncated and utf8_valid:
            try:
                raw_body = bounded_json_loads(
                    decoded,
                    label="API response JSON",
                    max_utf8_bytes=self.max_response_bytes,
                )
                json_parsed = True
            except ToolInputBoundsError:
                pass
        body = sanitize(raw_body)
        item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.HTTP_RESPONSE,
                source="httpx",
                source_identifier=f"{normalized_method} {safe_url}",
                summary=f"HTTP {status_code} from {host}",
                structured_data={
                    "status_code": status_code,
                    "body": body,
                    "elapsed_ms": elapsed_ms,
                    "truncated": truncated,
                    "json_parsed": json_parsed,
                    "utf8_valid": utf8_valid,
                },
            )
        )
        return ApiProbeResult(
            status_code=status_code,
            body=body,
            headers=headers,
            elapsed_ms=elapsed_ms,
            evidence_id=item.id,
            truncated=truncated,
            json_parsed=json_parsed,
            utf8_valid=utf8_valid,
        )
