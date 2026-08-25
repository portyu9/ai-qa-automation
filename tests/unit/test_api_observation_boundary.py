import gzip
import hashlib

import httpx
import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import EvidenceKind
from ai_qa_automation.tools.api_testing import ApiProbe, ApiProbeResult


def _probe(tmp_path, run_id: str, handler, *, max_response_bytes: int = 100_000) -> ApiProbe:
    return ApiProbe(
        EvidenceStore(tmp_path, run_id),
        allow_hosts={"example.com"},
        max_response_bytes=max_response_bytes,
        transport=httpx.MockTransport(handler),
    )


def _assert_rejected_observation(result: ApiProbeResult) -> None:
    assert result.status_code is None
    assert result.body is None
    assert result.headers == {}
    assert result.truncated is None
    assert result.json_parsed is False
    assert result.utf8_valid is None


@pytest.mark.asyncio
async def test_api_probe_forces_identity_accept_encoding(tmp_path):
    observed = None

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed
        observed = request.headers.get("accept-encoding")
        return httpx.Response(200, stream=httpx.ByteStream(b'{"ok":true}'), request=request)

    result = await _probe(tmp_path, "identity", handler).request(
        "GET", "https://example.com/data", headers={"Accept-Encoding": "gzip, br"}
    )
    assert observed == "identity"
    assert result.body == {"ok": True}
    assert result.json_parsed is True


@pytest.mark.asyncio
async def test_api_probe_rejects_encoded_response_before_decompression_or_body_read(tmp_path):
    class FailOnReadStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise AssertionError("encoded response body must not be iterated")
            yield b""  # pragma: no cover

        async def aclose(self) -> None:
            return None

    compressed = gzip.compress(b"x" * 1_000_000)
    assert compressed  # prove this fixture really represents an encoded body

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=FailOnReadStream(),
            headers={"Content-Encoding": "gzip"},
            request=request,
        )

    evidence = EvidenceStore(tmp_path, "encoded")
    probe = ApiProbe(
        evidence,
        allow_hosts={"example.com"},
        max_response_bytes=16,
        transport=httpx.MockTransport(handler),
    )
    result = await probe.request("GET", "https://example.com/data")

    _assert_rejected_observation(result)
    record = evidence.all()[-1]
    assert result.evidence_id == record.id
    assert record.kind == EvidenceKind.HTTP_RESPONSE
    assert record.structured_data["observation_error"] == "content_encoding"
    assert record.structured_data["response_body_observed"] is False
    assert "body" not in record.structured_data


@pytest.mark.asyncio
async def test_api_probe_rejects_excessive_header_count(tmp_path):
    headers = [(f"x-h-{index}", "v") for index in range(201)]

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=headers, stream=httpx.ByteStream(b"ok"), request=request)

    evidence = EvidenceStore(tmp_path, "headers-count")
    probe = ApiProbe(evidence, allow_hosts={"example.com"}, transport=httpx.MockTransport(handler))
    result = await probe.request("GET", "https://example.com/data")

    _assert_rejected_observation(result)
    record = evidence.all()[-1]
    assert record.structured_data["observation_error"] == "header_count"
    assert record.structured_data["response_body_observed"] is False
    assert "body" not in record.structured_data


@pytest.mark.asyncio
async def test_api_probe_rejects_excessive_aggregate_header_text(tmp_path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"x-large": "a" * 64_001},
            stream=httpx.ByteStream(b"ok"),
            request=request,
        )

    evidence = EvidenceStore(tmp_path, "headers-bytes")
    probe = ApiProbe(evidence, allow_hosts={"example.com"}, transport=httpx.MockTransport(handler))
    result = await probe.request("GET", "https://example.com/data")

    _assert_rejected_observation(result)
    record = evidence.all()[-1]
    assert record.structured_data["observation_error"] == "header_bytes"
    assert record.structured_data["response_body_observed"] is False
    assert "body" not in record.structured_data


@pytest.mark.asyncio
async def test_api_probe_parses_only_complete_strict_json(tmp_path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b'{"ok":true,"items":[1,2,3]}'),
            request=request,
        )

    result = await _probe(tmp_path, "valid-json", handler).request(
        "GET", "https://example.com/data"
    )
    assert result.body == {"ok": True, "items": [1, 2, 3]}
    assert result.truncated is False
    assert result.json_parsed is True
    assert result.utf8_valid is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        b'{"role":"user","role":"admin"}',
        b'{"value":NaN}',
        b"[" * 65 + b"0" + b"]" * 65,
    ],
)
async def test_api_probe_never_promotes_ambiguous_or_hostile_json_to_structure(tmp_path, payload):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(payload), request=request)

    result = await _probe(tmp_path, "strict-json", handler).request(
        "GET", "https://example.com/data"
    )
    assert isinstance(result.body, str)
    assert result.json_parsed is False
    assert result.truncated is False


@pytest.mark.asyncio
async def test_api_probe_never_parses_a_truncated_prefix_even_when_prefix_is_valid_json(tmp_path):
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"true trailing-data"), request=request)

    result = await _probe(tmp_path, "truncated-json", handler, max_response_bytes=4).request(
        "GET", "https://example.com/data"
    )
    assert result.body == "true"
    assert result.truncated is True
    assert result.json_parsed is False


@pytest.mark.asyncio
async def test_api_probe_exact_body_ceiling_is_complete_not_truncated(tmp_path):
    payload = b"exactly-16-bytes"
    assert len(payload) == 16

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(payload), request=request)

    result = await _probe(tmp_path, "exact-bound", handler, max_response_bytes=16).request(
        "GET", "https://example.com/data"
    )
    assert result.body == payload.decode("utf-8")
    assert result.truncated is False
    assert result.utf8_valid is True


@pytest.mark.asyncio
async def test_api_probe_total_timeout_bounds_stalled_body_stream(tmp_path):
    import asyncio

    from ai_qa_automation.tools.api_testing import ApiProbeTransportError

    class StalledStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.Event().wait()
            yield b""  # pragma: no cover

        async def aclose(self) -> None:
            return None

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=StalledStream(), request=request)

    evidence = EvidenceStore(tmp_path, "total-timeout")
    probe = ApiProbe(
        evidence,
        allow_hosts={"example.com"},
        timeout_seconds=0.02,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ApiProbeTransportError, match="total timeout budget") as caught:
        await probe.request("GET", "https://example.com/data")

    record = evidence.all()[-1]
    assert caught.value.evidence_id == record.id
    assert record.kind == EvidenceKind.NETWORK_ERROR
    assert record.structured_data["error_type"] == "TimeoutError"
    assert record.structured_data["error"] == "API probe exceeded its total timeout budget"


@pytest.mark.asyncio
async def test_api_probe_invalid_utf8_uses_bounded_digest_diagnostic_and_never_parses_json(
    tmp_path,
):
    payload = b'{"value":"\xff"}'

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(payload), request=request)

    result = await _probe(tmp_path, "invalid-utf8", handler).request(
        "GET", "https://example.com/data"
    )
    assert result.body == (
        f"<INVALID_UTF8_RESPONSE_BODY bytes={len(payload)} "
        f"sha256={hashlib.sha256(payload).hexdigest()}>"
    )
    assert result.utf8_valid is False
    assert result.json_parsed is False


@pytest.mark.asyncio
async def test_sut_json_cannot_collide_with_framework_rejection_state(tmp_path):
    payload = b'{"__framework_observation__":"REJECTED","reason":"content_encoding"}'

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(payload), request=request)

    result = await _probe(tmp_path, "sut-collision", handler).request(
        "GET", "https://example.com/data"
    )
    assert result.status_code == 200
    assert result.body == {
        "__framework_observation__": "REJECTED",
        "reason": "content_encoding",
    }
    assert result.truncated is False
    assert result.json_parsed is True


@pytest.mark.asyncio
async def test_internal_probe_api_preserves_bounded_observation_rejection_state(monkeypatch):
    import json
    import sys
    from types import SimpleNamespace

    from ai_qa_automation.runtime import internal_tools

    def tool(name, _description, _schema):
        def decorate(function):
            function._tool_name = name
            return function

        return decorate

    def create_sdk_mcp_server(*, name, version, tools):
        assert name == "qa"
        assert version == "1.0.0"
        return {item._tool_name: item for item in tools}

    monkeypatch.setitem(
        sys.modules,
        "claude_agent_sdk",
        SimpleNamespace(create_sdk_mcp_server=create_sdk_mcp_server, tool=tool),
    )

    class RejectingProbe:
        def __init__(self, *_args, **_kwargs):
            pass

        async def request(self, _method, _url):
            return ApiProbeResult(
                status_code=None,
                body=None,
                headers={},
                elapsed_ms=1.25,
                evidence_id="evidence-observation",
                truncated=None,
                json_parsed=False,
                utf8_valid=None,
            )

    monkeypatch.setattr(internal_tools, "ApiProbe", RejectingProbe)
    decision = SimpleNamespace(decision=SimpleNamespace(value="ALLOW"))
    state = SimpleNamespace(policy_decisions=[], evidence_ids=[])
    checkpoints: list[bool] = []
    services = SimpleNamespace(
        consume=lambda *_args: None,
        policy=SimpleNamespace(authorize_api_method=lambda *_args, **_kwargs: decision),
        allow_mutating_api_methods=False,
        state=state,
        network_hosts=lambda _url: {"example.com"},
        checkpoint=lambda: checkpoints.append(True),
        evidence=None,
    )

    server, _names = internal_tools.build_internal_mcp_server(services)
    output = await server["probe_api"]({"method": "GET", "url": "https://example.com/data"})
    payload = json.loads(output["content"][0]["text"])

    assert output.get("is_error") is not True
    assert payload == {
        "status_code": None,
        "elapsed_ms": 1.25,
        "evidence_id": "evidence-observation",
        "body": None,
        "truncated": None,
    }
    assert state.evidence_ids == ["evidence-observation"]
    assert checkpoints == [True]
