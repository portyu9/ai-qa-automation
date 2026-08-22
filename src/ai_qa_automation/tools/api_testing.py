from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind
from ..redaction import redact_text, sanitize

_MAX_API_RESPONSE_BYTES = 5_000_000


class ApiProbeTransportError(RuntimeError):
    """Transport failure that retains the evidence record created for the attempt."""

    def __init__(self, message: str, evidence_id: str) -> None:
        super().__init__(message)
        self.evidence_id = evidence_id


@dataclass(frozen=True)
class ApiProbeResult:
    status_code: int
    body: Any
    headers: dict[str, str]
    elapsed_ms: float
    evidence_id: str
    truncated: bool = False


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
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")
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

        started = time.monotonic()
        content = bytearray()
        truncated = False
        safe_url = redact_text(url)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                transport=self.transport,
                trust_env=False,
            ) as client:
                async with client.stream(
                    normalized_method,
                    url,
                    follow_redirects=False,
                    **kwargs,
                ) as response:
                    status_code = response.status_code
                    headers = sanitize(dict(response.headers))
                    async for chunk in response.aiter_bytes():
                        remaining = self.max_response_bytes - len(content)
                        if remaining <= 0:
                            truncated = True
                            break
                        content.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
        except httpx.RequestError as exc:
            elapsed_ms = (time.monotonic() - started) * 1000
            item = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.NETWORK_ERROR,
                    source="httpx",
                    source_identifier=f"{normalized_method} {safe_url}",
                    summary=f"HTTP transport failure contacting {host}",
                    structured_data={
                        "error_type": type(exc).__name__,
                        "error": redact_text(str(exc)),
                        "elapsed_ms": elapsed_ms,
                    },
                )
            )
            raise ApiProbeTransportError(redact_text(str(exc)), item.id) from exc
        elapsed_ms = (time.monotonic() - started) * 1000

        decoded = bytes(content).decode("utf-8", errors="replace")
        try:
            raw_body: Any = json.loads(decoded)
        except ValueError:
            raw_body = decoded
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
        )
