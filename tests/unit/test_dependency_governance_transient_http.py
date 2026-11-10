"""Dependency governance transport: bounded, fail-closed GitHub GET retries."""

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
SCRIPT = ROOT / ".github" / "scripts" / "dependency_governance.py"
API_PATH = "/pulls/17"
ENDPOINT = "https://api.github.com/repos/portyu9/ai-qa-automation" + API_PATH
GOOD = b'{"number":17,"state":"open"}'


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("governance_get_transport_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT.parent))
    return module


governance = _load()


def _network(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[int | bytes],
) -> tuple[governance.GitHubApi, list[tuple[str, str, int]], list[int]]:
    calls: list[tuple[str, str, int]] = []
    sleeps: list[int] = []
    remaining = iter(outcomes)

    def urlopen(request: Any, *, timeout: int) -> BytesIO:
        calls.append((request.get_method(), request.full_url, timeout))
        assert request.full_url == ENDPOINT
        assert request.get_header("Authorization") == "Bearer fixture-token"
        assert timeout == 30
        next_response = next(remaining)
        if type(next_response) is int:
            raise urllib.error.HTTPError(
                request.full_url,
                next_response,
                "fixture fault",
                {},
                BytesIO(b"GitHub test fault"),
            )
        return BytesIO(next_response)

    monkeypatch.setattr(governance.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(governance.time, "sleep", sleeps.append)
    api = governance.GitHubApi("fixture-token", "portyu9/ai-qa-automation")
    return api, calls, sleeps


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_transient_server_error_retries_authenticated_read_only(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _network(monkeypatch, [status, GOOD])
    assert api.get(API_PATH) == {"number": 17, "state": "open"}
    assert calls == [("GET", ENDPOINT, 30)] * 2
    assert sleeps == [governance.TRANSIENT_GET_DELAY_SECONDS]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_repeated_server_error_exhausts_bounded_attempts_without_success(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _network(
        monkeypatch, [status] * governance.TRANSIENT_GET_ATTEMPTS
    )
    with pytest.raises(governance.GovernanceError, match=f"failed HTTP {status}"):
        api.get(API_PATH)
    assert calls == [("GET", ENDPOINT, 30)] * governance.TRANSIENT_GET_ATTEMPTS
    assert sleeps == [governance.TRANSIENT_GET_DELAY_SECONDS] * (
        governance.TRANSIENT_GET_ATTEMPTS - 1
    )


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429])
def test_permanent_auth_policy_and_rate_limit_errors_are_never_retried(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _network(monkeypatch, [status])
    with pytest.raises(governance.GovernanceError, match=f"failed HTTP {status}"):
        api.get(API_PATH)
    assert calls == [("GET", ENDPOINT, 30)]
    assert sleeps == []


@pytest.mark.parametrize("method", ["POST", "PUT"])
def test_mutating_methods_never_retry_transient_http_500(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    api, calls, sleeps = _network(monkeypatch, [500])
    with pytest.raises(governance.GovernanceError, match="failed HTTP 500"):
        api.request(method, API_PATH, {"approve": False})
    assert calls == [(method, ENDPOINT, 30)]
    assert sleeps == []


def test_malformed_success_response_is_not_retired_as_good_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, calls, sleeps = _network(monkeypatch, [b'{"number":'])
    with pytest.raises(governance.GovernanceError, match="malformed JSON"):
        api.get(API_PATH)
    assert calls == [("GET", ENDPOINT, 30)]
    assert sleeps == []


def test_oversized_success_response_fails_closed_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, calls, sleeps = _network(monkeypatch, [b"12345"])
    with pytest.raises(governance.GovernanceError, match="bounded response size"):
        api.raw("GET", API_PATH, max_bytes=4)
    assert calls == [("GET", ENDPOINT, 30)]
    assert sleeps == []
