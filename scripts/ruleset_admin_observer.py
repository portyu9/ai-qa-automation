#!/usr/bin/env python3
"""Constrained observer for exact GitHub ruleset state requiring admin visibility."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com/"
API_VERSION = "2022-11-28"
EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_REPOSITORY_ID = 1341984495
EXPECTED_OWNER = "portyu9"
EXPECTED_OWNER_ID = 35150859
EXPECTED_RULESET_ID = 21201916
EXPECTED_RULESET_NAME = "Protect Main"
INSTALLATION_REPOSITORIES_ENDPOINT = "installation/repositories?per_page=100"
RULESET_ENDPOINT = f"repos/{EXPECTED_REPOSITORY}/rulesets/{EXPECTED_RULESET_ID}"
MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 20
GET_ATTEMPTS = 3
MAX_RETRY_AFTER_SECONDS = 5
TOKEN_EXPIRY_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _positive_int(value: Any, *, label: str) -> int:
    require(
        isinstance(value, int) and not isinstance(value, bool) and value > 0,
        f"{label} must be a positive integer",
    )
    return value


def _strict_json(text: str) -> Any:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate object key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(text, object_pairs_hook=pairs_hook)
    except json.JSONDecodeError as exc:
        raise ValueError(f"GitHub API response is not valid JSON: {exc}") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _validate_endpoint(method: str, endpoint: str, *, installation_id: int) -> str:
    require(method in {"GET", "POST"}, "ruleset observer method is outside reviewed allowlist")
    require(
        isinstance(endpoint, str) and endpoint == endpoint.strip() and bool(endpoint),
        "ruleset observer endpoint must be one nonempty trimmed string",
    )
    require(
        "\\" not in endpoint and not any(ord(character) < 0x20 for character in endpoint),
        "ruleset observer endpoint contains forbidden characters",
    )
    parsed = urllib.parse.urlsplit(endpoint)
    require(
        not parsed.scheme and not parsed.netloc and not parsed.fragment,
        "ruleset observer endpoint must be relative to api.github.com",
    )
    require(
        not parsed.path.startswith("/") and ".." not in parsed.path.split("/"),
        "ruleset observer endpoint must be traversal-free",
    )

    installation = f"app/installations/{installation_id}"
    token_mint = f"{installation}/access_tokens"
    allowed = {
        ("GET", installation),
        ("POST", token_mint),
        ("GET", INSTALLATION_REPOSITORIES_ENDPOINT),
        ("GET", RULESET_ENDPOINT),
    }
    require((method, endpoint) in allowed, "ruleset observer endpoint is outside reviewed allowlist")
    return endpoint


def _headers(token: str, *, json_body: bool) -> dict[str, str]:
    require(isinstance(token, str) and len(token) > 20, "ruleset observer credential is invalid")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "yp-ai-qa-ruleset-observer/1",
        "X-GitHub-Api-Version": API_VERSION,
    }
    if json_body:
        headers["Content-Type"] = "application/json"
    return headers


def _retry_delay(exc: urllib.error.HTTPError, attempt: int) -> float:
    retry_after = exc.headers.get("Retry-After") if exc.headers is not None else None
    if retry_after is not None and retry_after.isdigit():
        return min(float(retry_after), float(MAX_RETRY_AFTER_SECONDS))
    return min(float(2**attempt), float(MAX_RETRY_AFTER_SECONDS))


def _retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    if exc.code in {429, 502, 503, 504}:
        return True
    return (
        exc.code == 403
        and exc.headers is not None
        and exc.headers.get("X-RateLimit-Remaining") == "0"
    )


def _request_json(
    *,
    method: str,
    endpoint: str,
    token: str,
    installation_id: int,
    payload: dict[str, Any] | None = None,
    expected_status: int,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> Any:
    normalized = _validate_endpoint(method, endpoint, installation_id=installation_id)
    require(
        (method == "POST") == (payload is not None),
        "ruleset observer request body/method contract changed",
    )
    data = None if payload is None else _canonical_json(payload)
    url = urllib.parse.urljoin(API_ROOT, normalized)
    attempts = GET_ATTEMPTS if method == "GET" else 1

    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers=_headers(token, json_body=data is not None),
        )
        try:
            if opener is None:
                response_context = urllib.request.build_opener(NoRedirect()).open(
                    request,
                    timeout=TIMEOUT_SECONDS,
                )
            else:
                response_context = opener(request, timeout=TIMEOUT_SECONDS)
            with response_context as response:
                require(
                    response.status == expected_status,
                    f"ruleset observer {method} returned unexpected HTTP {response.status}",
                )
                require(
                    response.geturl() == url,
                    f"ruleset observer {method} was redirected",
                )
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= MAX_RESPONSE_BYTES,
                    "ruleset observer response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "ruleset observer response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("ruleset observer response is not UTF-8") from exc
            return _strict_json(text)
        except urllib.error.HTTPError as exc:
            if (
                method != "GET"
                or attempt + 1 >= attempts
                or not _retryable_http_error(exc)
            ):
                raise ValueError(
                    f"ruleset observer {method} returned HTTP {exc.code}"
                ) from exc
            sleeper(_retry_delay(exc, attempt))
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if method != "GET" or attempt + 1 >= attempts:
                raise ValueError(
                    f"ruleset observer {method} transport failed without safe retry"
                ) from exc
            sleeper(min(float(2**attempt), float(MAX_RETRY_AFTER_SECONDS)))

    raise ValueError("unreachable ruleset observer request state")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _mint_app_jwt(app_id: int, private_key: str, *, now: int) -> str:
    _positive_int(app_id, label="Ruleset Administration App id")
    require(bool(private_key.strip()), "App private key is invalid")
    header = _b64url(_canonical_json({"alg": "RS256", "typ": "JWT"}))
    payload = _b64url(
        _canonical_json({"exp": now + 540, "iat": now - 60, "iss": str(app_id)})
    )
    unsigned = f"{header}.{payload}".encode("ascii")

    runner_temp = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve()
    require(runner_temp.is_dir(), "RUNNER_TEMP must resolve to a directory")
    key_path: Path | None = None
    signed = b""
    try:
        fd, raw_path = tempfile.mkstemp(prefix="ruleset-observer-key.", dir=runner_temp)
        key_path = Path(raw_path)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(private_key.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        subprocess.run(
            ["openssl", "pkey", "-in", str(key_path), "-noout"],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        signed = subprocess.run(
            ["openssl", "dgst", "-binary", "-sha256", "-sign", str(key_path)],
            input=unsigned,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise ValueError("unable to validate/sign with Ruleset Administration App key") from exc
    finally:
        if key_path is not None:
            try:
                key_path.unlink()
            except FileNotFoundError:
                pass

    require(bool(signed), "App JWT signature is empty")
    return f"{unsigned.decode('ascii')}.{_b64url(signed)}"


def _validate_installation(raw: Any, *, app_id: int, installation_id: int) -> None:
    require(isinstance(raw, dict), "App installation response must be an object")
    require(raw.get("id") == installation_id, "App installation id drifted")
    require(raw.get("app_id") == app_id, "App id drifted")
    require(raw.get("target_type") == "User", "App installation target type drifted")
    account = raw.get("account")
    require(isinstance(account, dict), "App installation account is invalid")
    require(account.get("id") == EXPECTED_OWNER_ID, "App installation owner id drifted")
    require(account.get("login") == EXPECTED_OWNER, "App installation owner login drifted")
    require(
        raw.get("repository_selection") == "selected",
        "App installation repository selection drifted",
    )
    permissions = raw.get("permissions")
    require(isinstance(permissions, dict), "App installation permissions are invalid")
    require(
        permissions.get("administration") == "write",
        "App installation must retain Administration write",
    )
    require(
        set(permissions) <= {"administration", "metadata"},
        "App installation acquired unrelated repository permissions",
    )
    require(
        permissions.get("metadata", "read") == "read",
        "App installation metadata permission drifted",
    )


def _validate_installation_token(raw: Any, *, now: int) -> tuple[str, int]:
    require(isinstance(raw, dict), "installation token response must be an object")
    token = raw.get("token")
    require(isinstance(token, str) and len(token) > 20, "installation token is invalid")
    expires_at = raw.get("expires_at")
    require(
        isinstance(expires_at, str) and TOKEN_EXPIRY_RE.fullmatch(expires_at) is not None,
        "installation token expiry is invalid",
    )
    try:
        expiry = int(
            datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
        )
    except ValueError as exc:
        raise ValueError("installation token expiry is malformed") from exc
    require(expiry > now + 120, "installation token lifetime is too short")
    require(expiry <= now + 3700, "installation token lifetime exceeds reviewed bound")
    permissions = raw.get("permissions")
    require(isinstance(permissions, dict), "installation token permissions are invalid")
    require(
        permissions.get("administration") == "write",
        "ruleset observer token must use unavoidable Administration write visibility",
    )
    require(
        set(permissions) <= {"administration", "metadata"},
        "ruleset observer token acquired unrelated permissions",
    )
    require(
        permissions.get("metadata", "read") == "read",
        "ruleset observer token metadata permission drifted",
    )
    return token, expiry


def _validate_repository_scope(raw: Any) -> None:
    require(isinstance(raw, dict), "installation repositories response must be an object")
    require(raw.get("total_count") == 1, "ruleset observer token must be single-repository")
    repositories = raw.get("repositories")
    require(
        isinstance(repositories, list) and len(repositories) == 1,
        "ruleset observer repository scope is invalid",
    )
    repository = repositories[0]
    require(isinstance(repository, dict), "ruleset observer repository entry is invalid")
    require(repository.get("id") == EXPECTED_REPOSITORY_ID, "repository id drifted")
    require(repository.get("name") == "ai-qa-automation", "repository name drifted")
    require(repository.get("full_name") == EXPECTED_REPOSITORY, "repository full name drifted")
    owner = repository.get("owner")
    require(isinstance(owner, dict), "repository owner is invalid")
    require(owner.get("login") == EXPECTED_OWNER, "repository owner drifted")


def _validate_ruleset(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict), "ruleset response must be an object")
    require(raw.get("id") == EXPECTED_RULESET_ID, "ruleset id drifted")
    require(raw.get("name") == EXPECTED_RULESET_NAME, "ruleset name drifted")
    require(raw.get("target") == "branch", "ruleset target drifted")
    require(raw.get("source_type") == "Repository", "ruleset source type drifted")
    require(raw.get("source") == EXPECTED_REPOSITORY, "ruleset source drifted")
    require(
        isinstance(raw.get("bypass_actors"), list),
        "ruleset bypass actors are not observable with constrained observer",
    )
    return raw


def _atomic_write_json(path: Path, value: Any) -> None:
    require(path.is_absolute(), "ruleset observer output path must be absolute")
    runner_temp_text = os.environ.get("RUNNER_TEMP")
    require(isinstance(runner_temp_text, str) and bool(runner_temp_text), "RUNNER_TEMP is required")
    runner_temp = Path(runner_temp_text).resolve()
    parent = path.parent.resolve()
    require(parent == runner_temp, "ruleset observer output must remain directly under RUNNER_TEMP")
    parent_stat = parent.stat(follow_symlinks=False)
    require(stat.S_ISDIR(parent_stat.st_mode), "ruleset observer output parent is invalid")
    require(not path.exists() and not path.is_symlink(), "ruleset observer output already exists")

    temp_name = f".{path.name}.{os.getpid()}.tmp"
    temp_path = parent / temp_name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temp_path, flags, 0o600)
    try:
        payload = _canonical_json(value) + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            require(written > 0, "ruleset observer output write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temp_path, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def observe_ruleset(*, output: Path, now: int | None = None) -> None:
    require(os.environ.get("GITHUB_REPOSITORY") == EXPECTED_REPOSITORY, "repository drifted")
    app_id_text = os.environ.get("ADMIN_APP_ID", "")
    installation_id_text = os.environ.get("ADMIN_INSTALLATION_ID", "")
    private_key = os.environ.pop("ADMIN_PRIVATE_KEY", "")
    require(app_id_text.isdigit() and not app_id_text.startswith("0"), "App id is invalid")
    require(
        installation_id_text.isdigit() and not installation_id_text.startswith("0"),
        "installation id is invalid",
    )
    app_id = int(app_id_text)
    installation_id = int(installation_id_text)
    _positive_int(app_id, label="Ruleset Administration App id")
    _positive_int(installation_id, label="Ruleset Administration installation id")
    timestamp = int(time.time()) if now is None else now
    require(timestamp > 0, "observer clock is invalid")

    app_jwt = _mint_app_jwt(app_id, private_key, now=timestamp)
    private_key = ""
    installation = _request_json(
        method="GET",
        endpoint=f"app/installations/{installation_id}",
        token=app_jwt,
        installation_id=installation_id,
        expected_status=200,
    )
    _validate_installation(installation, app_id=app_id, installation_id=installation_id)

    token_response = _request_json(
        method="POST",
        endpoint=f"app/installations/{installation_id}/access_tokens",
        token=app_jwt,
        installation_id=installation_id,
        payload={
            "permissions": {"administration": "write"},
            "repositories": ["ai-qa-automation"],
        },
        expected_status=201,
    )
    app_jwt = ""
    installation_token, _ = _validate_installation_token(token_response, now=timestamp)
    token_response["token"] = ""

    repositories = _request_json(
        method="GET",
        endpoint=INSTALLATION_REPOSITORIES_ENDPOINT,
        token=installation_token,
        installation_id=installation_id,
        expected_status=200,
    )
    _validate_repository_scope(repositories)

    ruleset = _request_json(
        method="GET",
        endpoint=RULESET_ENDPOINT,
        token=installation_token,
        installation_id=installation_id,
        expected_status=200,
    )
    installation_token = ""
    validated = _validate_ruleset(ruleset)
    _atomic_write_json(output, validated)


def _self_test() -> None:
    installation_id = 123
    for method, endpoint in (
        ("GET", "app/installations/123"),
        ("POST", "app/installations/123/access_tokens"),
        ("GET", INSTALLATION_REPOSITORIES_ENDPOINT),
        ("GET", RULESET_ENDPOINT),
    ):
        require(
            _validate_endpoint(method, endpoint, installation_id=installation_id) == endpoint,
            "reviewed endpoint policy changed",
        )
    for method, endpoint in (
        ("PUT", RULESET_ENDPOINT),
        ("PATCH", RULESET_ENDPOINT),
        ("DELETE", RULESET_ENDPOINT),
        ("POST", RULESET_ENDPOINT),
        ("GET", "repos/portyu9/ai-qa-automation/issues"),
        ("GET", "../repos/portyu9/ai-qa-automation/rulesets/21201916"),
    ):
        try:
            _validate_endpoint(method, endpoint, installation_id=installation_id)
        except ValueError:
            pass
        else:
            raise ValueError(f"forbidden observer endpoint accepted: {method} {endpoint}")

    valid_ruleset = {
        "id": EXPECTED_RULESET_ID,
        "name": EXPECTED_RULESET_NAME,
        "target": "branch",
        "source_type": "Repository",
        "source": EXPECTED_REPOSITORY,
        "bypass_actors": [],
    }
    _validate_ruleset(valid_ruleset)
    invalid_ruleset = dict(valid_ruleset)
    invalid_ruleset.pop("bypass_actors")
    try:
        _validate_ruleset(invalid_ruleset)
    except ValueError:
        pass
    else:
        raise ValueError("observer accepted ruleset without bypass actor visibility")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Observe the exact Protect Main ruleset through a constrained App reader."
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        require(args.output is None, "--self-test does not accept --output")
        _self_test()
        print("Ruleset administration observer self-test passed")
        return 0
    require(args.output is not None, "--output is required")
    observe_ruleset(output=args.output)
    print(
        json.dumps(
            {
                "bypassActorsObservable": True,
                "decision": "ruleset-observed",
                "rulesetId": EXPECTED_RULESET_ID,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
