from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.api_testing import ApiProbe


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Accept": "application/json\r\nX-Action: delete"},
        {"Accept": "application/json\nX-Action: delete"},
        {"Accept": "application/json\rX-Action: delete"},
        {"Accept\r\nX-Action": "delete"},
        {b"Accept": b"application/json\r\nX-Action: delete"},
        {"Accept": "application/\u2603"},
        {b"Accept": b"application/\xff"},
    ],
)
async def test_request_header_injection_and_encoding_ambiguity_fail_before_transport(
    tmp_path: Path,
    headers: Any,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "header-injection"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PermissionError):
        await probe.request("GET", "https://example.com/v1/items", headers=headers)

    assert calls == 0
