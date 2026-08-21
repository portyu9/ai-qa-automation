from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind


@dataclass(frozen=True)
class ApiProbeResult:
    status_code: int
    body: Any
    headers: dict[str, str]
    elapsed_ms: float
    evidence_id: str


class ApiProbe:
    def __init__(self, evidence: EvidenceStore, *, allow_hosts: set[str] | None = None, timeout_seconds: float = 10) -> None:
        self.evidence = evidence
        self.allow_hosts = {host.lower() for host in (allow_hosts or set())}
        self.timeout_seconds = timeout_seconds

    async def request(self, method: str, url: str, **kwargs: Any) -> ApiProbeResult:
        host = (urlparse(url).hostname or "").lower()
        if not self.allow_hosts or host not in self.allow_hosts:
            raise PermissionError(f"network host is not allowlisted: {host or '<missing>'}")
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=False) as client:
            response = await client.request(method.upper(), url, **kwargs)
        try:
            body: Any = response.json()
        except ValueError:
            body = response.text[:10000]
        item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.HTTP_RESPONSE,
                source="httpx",
                source_identifier=f"{method.upper()} {url}",
                summary=f"HTTP {response.status_code} from {host}",
                structured_data={
                    "status_code": response.status_code,
                    "body": body,
                    "elapsed_ms": response.elapsed.total_seconds() * 1000,
                },
            )
        )
        return ApiProbeResult(
            status_code=response.status_code,
            body=body,
            headers=dict(response.headers),
            elapsed_ms=response.elapsed.total_seconds() * 1000,
            evidence_id=item.id,
        )
