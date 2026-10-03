from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import urllib.error

import pytest

import scripts.ruleset_admin_observer as observer


class _Headers(dict[str, str]):
    def get_content_type(self) -> str:
        return str(self.get("Content-Type", "application/json")).split(";", 1)[0]


class _Response:
    def __init__(
        self,
        url: str,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status = status
        self._url = url
        self._body = body
        self.headers = _Headers({"Content-Type": content_type})

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._body


def test_ruleset_observer_endpoint_policy_is_get_only_after_token_mint() -> None:
    installation_id = 123
    allowed = (
        ("GET", "app/installations/123"),
        ("POST", "app/installations/123/access_tokens"),
        ("GET", observer.INSTALLATION_REPOSITORIES_ENDPOINT),
        ("GET", observer.RULESET_ENDPOINT),
    )
    for method, endpoint in allowed:
        assert (
            observer._validate_endpoint(method, endpoint, installation_id=installation_id)
            == endpoint
        )

    forbidden = (
        ("PUT", observer.RULESET_ENDPOINT),
        ("PATCH", observer.RULESET_ENDPOINT),
        ("DELETE", observer.RULESET_ENDPOINT),
        ("POST", observer.RULESET_ENDPOINT),
        ("GET", "repos/portyu9/ai-qa-automation/issues"),
        ("GET", "../repos/portyu9/ai-qa-automation/rulesets/21201916"),
        ("GET", "https://api.github.com/repos/portyu9/ai-qa-automation/rulesets/21201916"),
    )
    for method, endpoint in forbidden:
        with pytest.raises(ValueError, match="allowlist|relative|traversal"):
            observer._validate_endpoint(method, endpoint, installation_id=installation_id)


def test_ruleset_observer_get_retries_only_bounded_transients() -> None:
    installation_id = 123
    endpoint = f"app/installations/{installation_id}"
    url = observer.API_ROOT + endpoint
    attempts = 0
    sleeps: list[float] = []

    def transient_then_success(request: object, *, timeout: int) -> _Response:
        nonlocal attempts
        assert timeout == observer.TIMEOUT_SECONDS
        attempts += 1
        if attempts == 1:
            raise urllib.error.HTTPError(
                url,
                503,
                "Service Unavailable",
                _Headers(),
                None,
            )
        return _Response(url, b'{"id":123}')

    result = observer._request_json(
        method="GET",
        endpoint=endpoint,
        token="x" * 32,
        installation_id=installation_id,
        expected_status=200,
        opener=transient_then_success,
        sleeper=sleeps.append,
    )

    assert result == {"id": 123}
    assert attempts == 2
    assert sleeps == [1.0]


def test_ruleset_observer_token_mint_is_never_replayed_after_transport_failure() -> None:
    installation_id = 123
    endpoint = f"app/installations/{installation_id}/access_tokens"
    attempts = 0

    def ambiguous_transport(_request: object, *, timeout: int) -> _Response:
        nonlocal attempts
        assert timeout == observer.TIMEOUT_SECONDS
        attempts += 1
        raise urllib.error.URLError("connection reset after submission")

    with pytest.raises(ValueError, match="without safe retry"):
        observer._request_json(
            method="POST",
            endpoint=endpoint,
            token="x" * 32,
            installation_id=installation_id,
            payload={
                "permissions": {"administration": "write"},
                "repositories": ["ai-qa-automation"],
            },
            expected_status=201,
            opener=ambiguous_transport,
            sleeper=lambda _delay: pytest.fail("POST must not sleep/retry"),
        )

    assert attempts == 1


def test_ruleset_observer_rejects_redirected_get() -> None:
    installation_id = 123
    endpoint = f"app/installations/{installation_id}"
    url = observer.API_ROOT + endpoint

    def redirected(_request: object, *, timeout: int) -> _Response:
        assert timeout == observer.TIMEOUT_SECONDS
        return _Response(url + "?redirected=1", b'{"id":123}')

    with pytest.raises(ValueError, match="redirected"):
        observer._request_json(
            method="GET",
            endpoint=endpoint,
            token="x" * 32,
            installation_id=installation_id,
            expected_status=200,
            opener=redirected,
            sleeper=lambda _delay: None,
        )


def test_ruleset_observer_installation_rejects_unrelated_permissions() -> None:
    raw = {
        "id": 123,
        "app_id": 456,
        "target_type": "User",
        "account": {"id": observer.EXPECTED_OWNER_ID, "login": observer.EXPECTED_OWNER},
        "repository_selection": "selected",
        "permissions": {
            "administration": "write",
            "metadata": "read",
            "contents": "write",
        },
    }

    with pytest.raises(ValueError, match="unrelated repository permissions"):
        observer._validate_installation(raw, app_id=456, installation_id=123)


def test_ruleset_observer_token_requires_exact_write_visibility_and_ttl() -> None:
    now = 1_800_000_000
    expires = datetime.fromtimestamp(now + 3600, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    valid = {
        "token": "x" * 32,
        "expires_at": expires,
        "permissions": {"administration": "write", "metadata": "read"},
    }
    token, expiry = observer._validate_installation_token(valid, now=now)
    assert token == "x" * 32
    assert expiry == now + 3600

    read_only = {
        **valid,
        "permissions": {"administration": "read", "metadata": "read"},
    }
    with pytest.raises(ValueError, match="unavoidable Administration write visibility"):
        observer._validate_installation_token(read_only, now=now)

    expanded = {
        **valid,
        "permissions": {
            "administration": "write",
            "metadata": "read",
            "contents": "read",
        },
    }
    with pytest.raises(ValueError, match="unrelated permissions"):
        observer._validate_installation_token(expanded, now=now)

    non_utc = {**valid, "expires_at": expires.replace("Z", "+00:00")}
    with pytest.raises(ValueError, match="expiry is invalid"):
        observer._validate_installation_token(non_utc, now=now)


def test_ruleset_observer_requires_exact_single_repository_scope() -> None:
    valid = {
        "total_count": 1,
        "repositories": [
            {
                "id": observer.EXPECTED_REPOSITORY_ID,
                "name": "ai-qa-automation",
                "full_name": observer.EXPECTED_REPOSITORY,
                "owner": {"login": observer.EXPECTED_OWNER},
            }
        ],
    }
    observer._validate_repository_scope(valid)

    widened = {
        "total_count": 2,
        "repositories": valid["repositories"] * 2,
    }
    with pytest.raises(ValueError, match="single-repository"):
        observer._validate_repository_scope(widened)


def test_ruleset_observer_requires_bypass_actor_visibility() -> None:
    valid = {
        "id": observer.EXPECTED_RULESET_ID,
        "name": observer.EXPECTED_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": observer.EXPECTED_REPOSITORY,
        "bypass_actors": [],
    }
    assert observer._validate_ruleset(valid)["bypass_actors"] == []

    for missing in ({k: v for k, v in valid.items() if k != "bypass_actors"}, {**valid, "bypass_actors": None}):
        with pytest.raises(ValueError, match="not observable"):
            observer._validate_ruleset(missing)


def test_ruleset_observer_atomic_output_is_runner_temp_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    output = tmp_path / "live-ruleset.json"
    observer._atomic_write_json(output, {"bypass_actors": []})

    assert output.read_text(encoding="utf-8") == '{"bypass_actors":[]}\n'
    assert output.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValueError, match="already exists"):
        observer._atomic_write_json(output, {"bypass_actors": []})

    outside = tmp_path / "nested" / "live.json"
    outside.parent.mkdir()
    with pytest.raises(ValueError, match="directly under RUNNER_TEMP"):
        observer._atomic_write_json(outside, {"bypass_actors": []})
