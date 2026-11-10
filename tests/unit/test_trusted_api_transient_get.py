"""Bounded read-only GitHub API retry on genuine transient status failures."""

from __future__ import annotations

from io import BytesIO
from typing import Any

import pytest

import scripts.auto_trusted_preflight as preflight

PATH = f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/77"
URL = f"https://api.github.com{PATH}"
GOOD = b'{"number":77,"state":"open"}'


class _Response(BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.headers = {"Content-Length": str(len(payload))}


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[int | bytes],
) -> tuple[preflight.GitHubAPI, list[tuple[str, str, int]], list[int]]:
    calls: list[tuple[str, str, int]] = []
    sleeps: list[int] = []
    remaining = iter(outcomes)

    def urlopen(request: Any, *, timeout: int) -> Any:
        calls.append((request.get_method(), request.full_url, timeout))
        assert request.get_method() == "GET"
        assert request.full_url == URL
        assert request.get_header("Authorization") == "Bearer fixture-token"
        assert timeout == 20
        outcome = next(remaining)
        if isinstance(outcome, int):
            raise preflight.urllib.error.HTTPError(
                request.full_url, outcome, "fixture HTTP fault", {}, None
            )
        return _Response(outcome)

    monkeypatch.setattr(preflight.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(preflight.time, "sleep", sleeps.append)
    api = preflight.GitHubAPI(
        api_url="https://api.github.com",
        token="fixture-token",
        repository=preflight.EXPECTED_REPOSITORY,
    )
    return api, calls, sleeps


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_transient_get_retries_once_and_uses_live_read_before_any_success(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _fixture(monkeypatch, [status, GOOD])
    assert api.get(PATH) == {"number": 77, "state": "open"}
    assert calls == [("GET", URL, 20)] * 2
    assert sleeps == [preflight.TRANSIENT_GET_DELAY_SECONDS]


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_bounded_server_errors_exhaust_into_failure_not_synthetic_pass(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _fixture(
        monkeypatch, [status] * preflight.TRANSIENT_GET_ATTEMPTS
    )
    with pytest.raises(RuntimeError, match=f"GitHub API GET failed with HTTP {status}"):
        api.get(PATH)
    assert calls == [("GET", URL, 20)] * preflight.TRANSIENT_GET_ATTEMPTS
    assert sleeps == [
        preflight.TRANSIENT_GET_DELAY_SECONDS
    ] * (preflight.TRANSIENT_GET_ATTEMPTS - 1)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429])
def test_policy_and_authentication_http_failures_are_never_retried(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    api, calls, sleeps = _fixture(monkeypatch, [status])
    with pytest.raises(RuntimeError, match=f"GitHub API GET failed with HTTP {status}"):
        api.get(PATH)
    assert calls == [("GET", URL, 20)]
    assert sleeps == []


def test_malformed_json_never_retried_or_treated_as_a_valid_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api, calls, sleeps = _fixture(monkeypatch, [b'{"number":'])
    with pytest.raises(ValueError, match="malformed JSON"):
        api.get(PATH)
    assert calls == [("GET", URL, 20)]
    assert sleeps == []
