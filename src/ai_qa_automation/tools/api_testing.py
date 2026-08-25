from __future__ import annotations

import asyncio
import hashlib
import math
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind
from ..redaction import redact_text, sanitize
from ..runtime.tool_input_bounds import ToolInputBoundsError, bounded_json_loads

_MAX_API_RESPONSE_BYTES = 5_000_000
_MAX_API_TIMEOUT_SECONDS = 900
_MAX_API_RESPONSE_HEADERS = 200
_MAX_API_RESPONSE_HEADER_BYTES = 64_000
_API_RAW_CHUNK_BYTES = 64_000


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
    total = 0
    count = 0
    for name, value in headers.multi_items():
        count += 1
        if count > _MAX_API_RESPONSE_HEADERS:
            raise _ObservationBoundaryViolation(
                "header_count",
                "API response exceeds the header-count bound",
            )
        total += _utf8_bytes_bounded(name, remaining=_MAX_API_RESPONSE_HEADER_BYTES - total)
        total += _utf8_bytes_bounded(value, remaining=_MAX_API_RESPONSE_HEADER_BYTES - total)
    sanitized = sanitize(dict(headers))
    if not isinstance(sanitized, dict):  # pragma: no cover - sanitize preserves mappings
        raise TypeError("sanitized API response headers must remain a mapping")
    return {str(key): str(value) for key, value in sanitized.items()}


def _identity_request_headers(value: Any) -> httpx.Headers:
    headers = httpx.Headers(value)
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
        self.allow_hosts = {
            str(host).strip().lower() for host in (allow_hosts or set()) if str(host).strip()
        }
        self.allowed_methods = {
            str(method).strip().upper()
            for method in (allowed_methods or {"GET", "HEAD", "OPTIONS"})
            if str(method).strip()
        }
        self.timeout_seconds = float(timeout_seconds)
        self.max_response_bytes = max_response_bytes
        self.transport = transport

    async def request(self, method: str, url: str, **kwargs: Any) -> ApiProbeResult:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        normalized_method = method.upper().strip()
        if parsed.scheme not in {"http", "https"}:
            raise PermissionError("API probe supports HTTP(S) URLs only")
        if not self.allow_hosts or host not in self.allow_hosts:
            raise PermissionError(f"network host is not allowlisted: {host or '<missing>'}")
        if normalized_method not in self.allowed_methods:
            raise PermissionError(
                f"HTTP method is not allowlisted: {normalized_method or '<missing>'}"
            )
        if kwargs.get("follow_redirects") not in (None, False):
            raise PermissionError("API probe redirects are disabled by adapter policy")
        kwargs.pop("follow_redirects", None)
        kwargs["headers"] = _identity_request_headers(kwargs.get("headers"))

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
                    follow_redirects=False,
                    **kwargs,
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
                body={
                    "__framework_observation__": "REJECTED",
                    "reason": exc.code,
                    "observed_status_code": status_code,
                    "response_body_observed": False,
                },
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
