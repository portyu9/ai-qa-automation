"""Bounded, authenticated owner-identity GET retry across dependency and security lanes."""

from __future__ import annotations

import importlib.util
import sys
import urllib.error
from io import BytesIO
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
OWNER_URL = "https://api.github.com/user"
GOOD = b'{"login":"portyu9","id":35150859,"type":"User"}'
WRONG_OWNER = b'{"login":"github-actions[bot]","id":41898282,"type":"Bot"}'
LANES = ("dependency_user_approval", "security_owner_review")


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"bounded_owner_identity_{name}", SCRIPT_DIR / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


MODULES = {name: _load(name) for name in LANES}


class _Response(BytesIO):
    def __init__(self, payload: bytes, *, content_length: int | None = None) -> None:
        super().__init__(payload)
        self.headers = {
            "Content-Length": str(len(payload) if content_length is None else content_length)
        }


def _network(
    monkeypatch: pytest.MonkeyPatch,
    lane: str,
    outcomes: list[int | bytes],
    *,
    declared_length: int | None = None,
) -> tuple[ModuleType, list[tuple[str, str, int]], list[int]]:
    module = MODULES[lane]
    calls: list[tuple[str, str, int]] = []
    sleeps: list[int] = []
    remaining = iter(outcomes)

    def urlopen(request: Any, *, timeout: int) -> _Response:
        calls.append((request.get_method(), request.full_url, timeout))
        assert request.get_method() == "GET"
        assert request.full_url == OWNER_URL
        assert request.get_header("Authorization") == "Bearer owner-fixture-token"
        assert timeout == 20
        result = next(remaining)
        if type(result) is int:
            raise urllib.error.HTTPError(
                request.full_url,
                result,
                "fixture transient or permanent error",
                {},
                BytesIO(b"GitHub fixture failure"),
            )
        return _Response(result, content_length=declared_length)

    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    return module, calls, sleeps


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_transient_authenticated_get_retries_before_exact_owner_decision(
    monkeypatch: pytest.MonkeyPatch, lane: str, status: int
) -> None:
    module, calls, sleeps = _network(monkeypatch, lane, [status, GOOD])
    assert module._review_token_identity("owner-fixture-token") == {
        "login": "portyu9",
        "id": 35150859,
        "type": "User",
    }
    assert calls == [("GET", OWNER_URL, 20)] * 2
    assert sleeps == [module.TRANSIENT_IDENTITY_DELAY_SECONDS]


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_exhausted_server_errors_fail_closed_after_exact_attempt_bound(
    monkeypatch: pytest.MonkeyPatch, lane: str, status: int
) -> None:
    module, calls, sleeps = _network(
        monkeypatch, lane, [status] * MODULES[lane].TRANSIENT_IDENTITY_ATTEMPTS
    )
    with pytest.raises(module.GovernanceError, match=f"identity lookup failed HTTP {status}"):
        module._review_token_identity("owner-fixture-token")
    assert calls == [("GET", OWNER_URL, 20)] * module.TRANSIENT_IDENTITY_ATTEMPTS
    assert sleeps == [module.TRANSIENT_IDENTITY_DELAY_SECONDS] * (
        module.TRANSIENT_IDENTITY_ATTEMPTS - 1
    )


@pytest.mark.parametrize("lane", LANES)
@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429])
def test_unauthorized_policy_and_rate_limit_http_errors_never_retry(
    monkeypatch: pytest.MonkeyPatch, lane: str, status: int
) -> None:
    module, calls, sleeps = _network(monkeypatch, lane, [status])
    with pytest.raises(module.GovernanceError, match=f"identity lookup failed HTTP {status}"):
        module._review_token_identity("owner-fixture-token")
    assert calls == [("GET", OWNER_URL, 20)]
    assert sleeps == []


@pytest.mark.parametrize("lane", LANES)
def test_recovered_http_500_cannot_authorize_wrong_user_identity(
    monkeypatch: pytest.MonkeyPatch, lane: str
) -> None:
    module, calls, sleeps = _network(monkeypatch, lane, [500, WRONG_OWNER])
    with pytest.raises(module.GovernanceError, match="differs from exact repository owner"):
        module._review_token_identity("owner-fixture-token")
    assert calls == [("GET", OWNER_URL, 20)] * 2
    assert sleeps == [module.TRANSIENT_IDENTITY_DELAY_SECONDS]


@pytest.mark.parametrize("lane", LANES)
def test_malformed_json_fails_without_retry_or_owner_identity(
    monkeypatch: pytest.MonkeyPatch, lane: str
) -> None:
    module, calls, sleeps = _network(monkeypatch, lane, [b'{"login":'])
    with pytest.raises(module.GovernanceError, match="malformed JSON"):
        module._review_token_identity("owner-fixture-token")
    assert calls == [("GET", OWNER_URL, 20)]
    assert sleeps == []


@pytest.mark.parametrize("lane", LANES)
def test_oversized_response_fails_without_retry_or_owner_identity(
    monkeypatch: pytest.MonkeyPatch, lane: str
) -> None:
    length = MODULES[lane].MAX_RESPONSE_BYTES + 1
    module, calls, sleeps = _network(monkeypatch, lane, [GOOD], declared_length=length)
    with pytest.raises(module.GovernanceError, match="exceeds bounded size"):
        module._review_token_identity("owner-fixture-token")
    assert calls == [("GET", OWNER_URL, 20)]
    assert sleeps == []


@pytest.mark.parametrize("lane", LANES)
def test_missing_owner_token_fails_before_any_network_read(
    monkeypatch: pytest.MonkeyPatch, lane: str
) -> None:
    module, calls, sleeps = _network(monkeypatch, lane, [])
    with pytest.raises(module.GovernanceError, match="is required"):
        module._review_token_identity("")
    assert calls == []
    assert sleeps == []
