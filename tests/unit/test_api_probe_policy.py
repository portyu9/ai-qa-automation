import math

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.api_testing import ApiProbe


@pytest.mark.asyncio
async def test_api_probe_is_fail_closed_without_host_allowlist(tmp_path):
    probe = ApiProbe(EvidenceStore(tmp_path, "run"), allow_hosts=set())
    with pytest.raises(PermissionError):
        await probe.request("GET", "https://example.com")


@pytest.mark.asyncio
async def test_api_probe_blocks_mutating_method_by_default_before_network(tmp_path):
    probe = ApiProbe(EvidenceStore(tmp_path, "run-method"), allow_hosts={"example.com"})
    with pytest.raises(PermissionError, match="HTTP method"):
        await probe.request("DELETE", "https://example.com/resource")


@pytest.mark.asyncio
async def test_api_probe_rejects_non_http_scheme(tmp_path):
    probe = ApiProbe(EvidenceStore(tmp_path, "run-scheme"), allow_hosts={"example.com"})
    with pytest.raises(PermissionError, match="HTTP\\(S\\)"):
        await probe.request("GET", "file://example.com/etc/passwd")


@pytest.mark.asyncio
async def test_api_probe_caller_cannot_enable_redirect_following(tmp_path):
    probe = ApiProbe(EvidenceStore(tmp_path, "run-redirect"), allow_hosts={"example.com"})

    with pytest.raises(PermissionError, match="redirects are disabled"):
        await probe.request("GET", "https://example.com", follow_redirects=True)


@pytest.mark.asyncio
async def test_api_probe_bounds_response_body_and_marks_truncation(tmp_path):
    import httpx

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"x" * 100), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "run-bounded"),
        allow_hosts={"example.com"},
        max_response_bytes=16,
        transport=httpx.MockTransport(handler),
    )
    result = await probe.request("GET", "https://example.com/large")
    assert result.body == "x" * 16
    assert result.truncated is True
    assert result.json_parsed is False
    assert result.utf8_valid is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": math.inf},
        {"max_response_bytes": 0},
    ],
)
def test_api_probe_rejects_invalid_resource_bounds(tmp_path, kwargs):
    with pytest.raises(ValueError):
        ApiProbe(EvidenceStore(tmp_path, "run-invalid-bounds"), **kwargs)


@pytest.mark.asyncio
async def test_api_probe_preserves_transport_failure_as_evidence(tmp_path):
    import httpx

    from ai_qa_automation.models import EvidenceKind
    from ai_qa_automation.tools.api_testing import ApiProbeTransportError

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused token=super-secret-token", request=request)

    evidence = EvidenceStore(tmp_path, "run-network-failure")
    probe = ApiProbe(
        evidence,
        allow_hosts={"example.com"},
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ApiProbeTransportError) as caught:
        await probe.request("GET", "https://example.com/data?token=super-secret-token")

    records = evidence.all()
    assert caught.value.evidence_id == records[-1].id
    assert records[-1].kind == EvidenceKind.NETWORK_ERROR
    assert "super-secret-token" not in records[-1].source_identifier
    assert "super-secret-token" not in str(records[-1].structured_data)
