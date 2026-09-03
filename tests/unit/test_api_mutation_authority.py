from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from pydantic import ValidationError

from ai_qa_automation.api_authority import classify_api_observation_request
from ai_qa_automation.config import Settings
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, ToolDecision
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.internal_tool_domains.common import RuntimeServices
from ai_qa_automation.tools.api_testing import ApiProbe


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutating_methods_remain_denied_even_under_legacy_enablement(
    tmp_path: Path, method: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    policy = PolicyEngine(tmp_path, target)

    decision = policy.authorize_api_method(method, allow_mutating=True)

    assert decision.decision is ToolDecision.DENY
    assert decision.rule_id == "API-WRITE-001"


def test_legacy_mutating_api_setting_true_is_invalid_configuration(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="generic mutating API methods are not supported"):
        Settings(control_root=tmp_path, allow_mutating_api_methods=True)


def test_legacy_mutating_api_environment_true_is_invalid_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AI_QA_ALLOW_MUTATING_API_METHODS", "true")

    with pytest.raises(ValidationError, match="generic mutating API methods are not supported"):
        Settings(control_root=tmp_path)


def test_direct_runtime_services_cannot_restore_legacy_mutation_authority(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot authorize generic remote mutation"):
        RuntimeServices(
            workspace=tmp_path,
            state=AgentRunState(objective="observe API", workspace=str(tmp_path)),
            evidence=cast(Any, object()),
            policy=cast(Any, object()),
            test_runner=cast(Any, object()),
            max_tool_calls=3,
            max_repeated_action=2,
            allow_mutating_api_methods=True,
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/v1/delete/123",
        "https://example.com/v1/%2564elete/123",
        "https://example.com/v1/items?action=remove",
        "https://example.com/v1/items?op=reset",
        "https://example.com/v1/items?delete=true",
    ],
)
def test_action_semantics_are_denied_even_with_safe_http_method(url: str) -> None:
    authority = classify_api_observation_request("GET", url)
    assert authority.allowed is False
    assert authority.code == "action_semantics"


def test_excessively_nested_url_encoding_fails_closed_instead_of_bypassing_actions() -> None:
    encoded = "delete"
    for _ in range(6):
        encoded = encoded.replace("%", "%25") if "%" in encoded else "%64elete"
    authority = classify_api_observation_request(
        "GET",
        f"https://example.com/v1/{encoded}/123",
    )
    assert authority.allowed is False
    assert authority.code in {"action_semantics", "encoding_bounds"}


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/v1/runs/123",
        "https://example.com/v1/updated-items",
        "https://example.com/v1/items?action=list",
        "https://example.com/v1/items?operation=status",
    ],
)
def test_resource_nouns_and_non_mutating_query_values_are_not_false_positive_actions(
    url: str,
) -> None:
    authority = classify_api_observation_request("GET", url)
    assert authority.allowed is True


@pytest.mark.asyncio
async def test_api_probe_rejects_mutation_and_action_semantics_before_transport(
    tmp_path: Path,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "read-only"),
        allow_hosts={"example.com"},
        transport=httpx.MockTransport(handler),
    )

    for method, url in (
        ("DELETE", "https://example.com/v1/items/1"),
        ("GET", "https://example.com/v1/reset/1"),
        ("GET", "https://example.com/v1/items?action=delete"),
    ):
        with pytest.raises(PermissionError):
            await probe.request(method, url)

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "request_kwargs",
    [
        {"params": {"action": "delete"}},
        {"json": {"action": "delete"}},
        {"data": {"action": "delete"}},
        {"content": b'{"action":"delete"}'},
        {"cookies": {"action": "delete"}},
    ],
)
async def test_api_probe_rejects_post_classification_request_modifiers_before_transport(
    tmp_path: Path,
    request_kwargs: dict[str, Any],
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "request-modifiers"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PermissionError, match="request modifiers are not authorized"):
        await probe.request("GET", "https://example.com/v1/items", **request_kwargs)

    assert calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "admin.example.com"},
        {"Content-Type": "application/json"},
        {"Content-Length": "0"},
        {"Transfer-Encoding": "chunked"},
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-Method-Override": "PATCH"},
        {"X-Original-Method": "POST"},
        {"X-Action": "delete"},
        {"X-Operation": "reset"},
        {"Cookie": "action=delete"},
    ],
)
async def test_api_probe_rejects_unreviewed_request_headers_before_transport(
    tmp_path: Path,
    headers: dict[str, str],
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "request-headers"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PermissionError, match="request header is not authorized"):
        await probe.request("GET", "https://example.com/v1/items", headers=headers)

    assert calls == 0


@pytest.mark.asyncio
async def test_api_probe_rejects_request_header_resource_exhaustion_before_transport(
    tmp_path: Path,
) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "request-header-bounds"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )

    too_many = [("Accept", "v") for _ in range(65)]
    with pytest.raises(PermissionError, match="64-header bound"):
        await probe.request("GET", "https://example.com/v1/items", headers=too_many)
    with pytest.raises(PermissionError, match="aggregate byte bound"):
        await probe.request(
            "GET",
            "https://example.com/v1/items",
            headers={"Accept": "a" * 16_385},
        )

    assert calls == 0


@pytest.mark.asyncio
async def test_api_probe_rejects_unbounded_header_iterables_without_consuming_them(
    tmp_path: Path,
) -> None:
    calls = 0
    iterated = False

    class UnboundedHeaders:
        def __iter__(self):
            nonlocal iterated
            iterated = True
            while True:
                yield ("Accept", "application/json")

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "unbounded-request-headers"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(PermissionError, match="bounded mapping or sequence"):
        await probe.request(
            "GET",
            "https://example.com/v1/items",
            headers=UnboundedHeaders(),
        )

    assert iterated is False
    assert calls == 0


@pytest.mark.asyncio
async def test_api_probe_allows_only_reviewed_observation_headers(tmp_path: Path) -> None:
    observed: httpx.Headers | None = None

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal observed
        observed = request.headers
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"), request=request)

    probe = ApiProbe(
        EvidenceStore(tmp_path, "allowed-request-headers"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )
    await probe.request(
        "GET",
        "https://example.com/v1/items",
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer opaque-test-token",
            "Accept-Encoding": "gzip",
        },
    )

    assert observed is not None
    assert observed["accept"] == "application/json"
    assert observed["authorization"] == "Bearer opaque-test-token"
    assert observed["accept-encoding"] == "identity"


@pytest.mark.parametrize("allowed_methods", [{"POST"}, {"GET", "DELETE"}, set()])
def test_api_probe_constructor_cannot_widen_observation_method_authority(
    tmp_path: Path, allowed_methods: set[str]
) -> None:
    with pytest.raises(ValueError):
        ApiProbe(
            EvidenceStore(tmp_path, "method-constructor"),
            allow_hosts={"example.com"},
            allowed_methods=allowed_methods,
        )


@pytest.mark.asyncio
async def test_read_only_probe_semantics_remain_operational(tmp_path: Path) -> None:
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            stream=httpx.ByteStream(b'{"ok":true}'),
            request=request,
        )

    probe = ApiProbe(
        EvidenceStore(tmp_path, "read-compatible"),
        allow_hosts={"example.com"},
        external_egress_enforced=True,
        transport=httpx.MockTransport(handler),
    )
    result = await probe.request("GET", "https://example.com/v1/items?limit=1")

    assert calls == 1
    assert result.status_code == 200
    assert result.body == {"ok": True}
    assert result.json_parsed is True
