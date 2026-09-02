from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .core import (
    EXPECTED_REPOSITORY,
    EXPECTED_REPOSITORY_ID,
    MAX_DELIVERY_ID,
    MAX_POLICY_BYTES,
    MAX_WEBHOOK_BYTES,
    OneShotPolicy,
    Wakeup,
    parse_workflow_run_wakeup,
    verify_webhook_signature,
)
from .dynamodb_store import DynamoDeliveryStore
from .github import AppTokenProvider, GitHubClient
from .service import ServiceConfig, TrustedGateService

CONFIG_PREFIX_ENV = "TRUSTED_GATE_CONFIG_PREFIX"
TABLE_ENV = "TRUSTED_GATE_TABLE_NAME"
POLICY_SHA_ENV = "TRUSTED_GATE_POLICY_SHA256"
EXPECTED_PATH = "/github/webhook"
MIN_WEBHOOK_SECRET_BYTES = 32
MAX_WEBHOOK_SECRET_BYTES = 4096
MAX_SSM_STANDARD_VALUE_BYTES = 4096
MAX_SECURESTRING_CIPHERTEXT_BYTES = 16 * 1024
MAX_PARAMETER_PREFIX_BYTES = 768
MAX_PARAMETER_PREFIX_DEPTH = 12
WEBHOOK_SECRET_CACHE_TTL_SECONDS = 300.0
WEBHOOK_SECRET_CACHE_MAX_USES = 1024
PARAMETER_PREFIX_RE = re.compile(r"^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
WEBHOOK_SIGNATURE_RE = re.compile(r"^sha256=[0-9a-f]{64}$")
DELIVERY_HEADER_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
APP_SIGNING_PARAMETER_SUFFIX = "-".join(("private", "key"))
HOOK_AUTH_PARAMETER_SUFFIX = "-".join(("webhook", "secret"))
PUBLIC_PARAMETER_SUFFIXES = {
    "app_id": "app-id",
    "bot_login": "bot-login",
    "installation_id": "installation-id",
    "repository": "repository",
    "repository_id": "repository-id",
}
STATIC_PARAMETER_SUFFIXES = {
    **PUBLIC_PARAMETER_SUFFIXES,
    "private_key": APP_SIGNING_PARAMETER_SUFFIX,
}
WEBHOOK_SECRET_SUFFIX = HOOK_AUTH_PARAMETER_SUFFIX
POLICY_PARAMETER_SUFFIX = "policy"
ZERO_POLICY_SHA = "0" * 64

FailureStage = Literal[
    "webhook_auth",
    "static_config",
    "policy_load",
    "service_construct",
    "delivery_acquire_or_handle",
]
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PublicConfig:
    app_id: str
    installation_id: int
    repository: str
    repository_id: int
    bot_login: str


@dataclass(frozen=True)
class StaticConfig:
    webhook_secret: bytes
    app_id: str
    installation_id: int
    private_key_pem: str
    repository: str
    repository_id: int
    bot_login: str


@dataclass
class _WebhookSecretCache:
    secret: bytes
    version: int
    ciphertext_sha256: bytes
    expires_at: float
    remaining_uses: int


_ssm_client: Any | None = None
_dynamodb_client: Any | None = None
_webhook_secret_cache: _WebhookSecretCache | None = None
_webhook_secret_cache_lock = threading.Lock()


def handler(event: Any, context: Any) -> dict[str, Any]:
    del context
    stage: FailureStage = "webhook_auth"
    try:
        headers, body = _parse_function_url_event(event)
        webhook_secret = _load_webhook_secret()
        verify_webhook_signature(
            secret=webhook_secret,
            body=body,
            signature_header=headers.get("x-hub-signature-256"),
        )

        expected_policy_sha = _policy_pin()
        if expected_policy_sha == ZERO_POLICY_SHA:
            return _response(202, {"outcome": "BLOCKED"})

        stage = "policy_load"
        policy_bytes, policy_sha256 = _load_policy(expected_sha=expected_policy_sha)
        policy = OneShotPolicy.parse(policy_bytes)
        wakeup = parse_workflow_run_wakeup(
            event_header=headers.get("x-github-event"),
            delivery_header=headers.get("x-github-delivery"),
            body=body,
        )
        _prefilter_authenticated_wakeup(policy, wakeup)

        stage = "static_config"
        public = _load_public_config()
        if wakeup.installation_id != public.installation_id:
            raise PermissionError("webhook installation identity is not authorized")
        private_key_pem = _load_private_key()
        config = StaticConfig(
            webhook_secret=webhook_secret,
            app_id=public.app_id,
            installation_id=public.installation_id,
            private_key_pem=private_key_pem,
            repository=public.repository,
            repository_id=public.repository_id,
            bot_login=public.bot_login,
        )

        stage = "service_construct"
        service = _build_service(config, policy_bytes=policy_bytes, policy_sha256=policy_sha256)
        stage = "delivery_acquire_or_handle"
        result = service.handle_delivery(
            event_header=headers.get("x-github-event"),
            delivery_header=headers.get("x-github-delivery"),
            signature_header=headers.get("x-hub-signature-256"),
            body=body,
        )
    except PermissionError as exc:
        _log_failure(stage, exc)
        return _response(403, {"outcome": "REJECTED"})
    except ValueError as exc:
        _log_failure(stage, exc)
        return _response(400, {"outcome": "INVALID"})
    except Exception as exc:
        _log_failure(stage, exc)
        return _response(503, {"outcome": "INFRASTRUCTURE_FAILURE"}, retry_after=True)

    payload = {
        "outcome": result.outcome,
        "delivery_id": result.delivery_id,
        "status_published": result.status_published,
    }
    if result.outcome == "SUCCESS":
        return _response(200, payload)
    if result.outcome == "BLOCKED":
        return _response(202, payload)
    return _response(503, payload, retry_after=True)


def _parse_function_url_event(event: Any) -> tuple[dict[str, str], bytes]:
    if not isinstance(event, dict):
        raise ValueError("Lambda event must be an object")
    request_context = event.get("requestContext")
    if not isinstance(request_context, dict):
        raise ValueError("Lambda request context is missing")
    http = request_context.get("http")
    if not isinstance(http, dict) or http.get("method") != "POST":
        raise ValueError("Lambda webhook requires POST")
    if event.get("rawPath") != EXPECTED_PATH:
        raise ValueError("Lambda webhook path is not authorized")

    raw_headers = event.get("headers")
    if not isinstance(raw_headers, dict):
        raise ValueError("Lambda headers are missing")
    headers: dict[str, str] = {}
    for key, value in raw_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("Lambda headers are malformed")
        lowered = key.lower()
        if lowered in headers:
            raise ValueError("Lambda headers contain duplicate normalized names")
        headers[lowered] = value
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ValueError("Lambda webhook content type must be application/json")
    if not headers.get("user-agent", "").startswith("GitHub-Hookshot/"):
        raise PermissionError("Lambda webhook user agent is not GitHub Hookshot")
    _precheck_webhook_headers(headers)

    rendered = event.get("body")
    if not isinstance(rendered, str):
        raise ValueError("Lambda webhook body is missing")
    encoded = event.get("isBase64Encoded")
    if encoded is True:
        try:
            body = base64.b64decode(rendered, validate=True)
        except ValueError as exc:
            raise ValueError("Lambda webhook body is invalid base64") from exc
    elif encoded is False or encoded is None:
        body = rendered.encode("utf-8")
    else:
        raise ValueError("Lambda base64 flag is malformed")
    if not body or len(body) > MAX_WEBHOOK_BYTES:
        raise ValueError("Lambda webhook body is outside configured bounds")
    return headers, body


def _precheck_webhook_headers(headers: dict[str, str]) -> None:
    signature = headers.get("x-hub-signature-256")
    if not isinstance(signature, str) or WEBHOOK_SIGNATURE_RE.fullmatch(signature) is None:
        raise PermissionError("Lambda webhook signature header is malformed")
    if headers.get("x-github-event") != "workflow_run":
        raise ValueError("Lambda webhook event is not workflow_run")
    delivery = headers.get("x-github-delivery")
    if (
        not isinstance(delivery, str)
        or not delivery
        or len(delivery) > MAX_DELIVERY_ID
        or not delivery.isascii()
        or DELIVERY_HEADER_RE.fullmatch(delivery) is None
    ):
        raise ValueError("Lambda webhook delivery header is malformed")


def _parameter_row(
    response: Any,
    *,
    expected_name: str,
    expected_type: str,
    require_value: bool,
) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise RuntimeError("SSM parameter response is malformed")
    parameter = response.get("Parameter")
    if not isinstance(parameter, dict) or parameter.get("Name") != expected_name:
        raise RuntimeError("SSM parameter identity is missing or malformed")
    if parameter.get("Type") != expected_type:
        raise RuntimeError("SSM parameter type differs from reviewed configuration")
    version = parameter.get("Version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RuntimeError("SSM parameter version is missing or malformed")
    value = parameter.get("Value")
    if require_value and not isinstance(value, str):
        raise RuntimeError("SSM parameter value is malformed")
    return parameter


def _secure_string_ciphertext_sha256(parameter: dict[str, Any]) -> bytes:
    value = parameter.get("Value")
    if not isinstance(value, str):
        raise RuntimeError("SecureString ciphertext is missing or malformed")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > MAX_SECURESTRING_CIPHERTEXT_BYTES:
        raise RuntimeError("SecureString ciphertext is outside bounds")
    return hashlib.sha256(encoded).digest()


def _load_webhook_secret() -> bytes:
    global _webhook_secret_cache

    name = _parameter_name(WEBHOOK_SECRET_SUFFIX)
    with _webhook_secret_cache_lock:
        metadata = _parameter_row(
            _ssm().get_parameter(Name=name, WithDecryption=False),
            expected_name=name,
            expected_type="SecureString",
            require_value=True,
        )
        version = int(metadata["Version"])
        ciphertext_sha256 = _secure_string_ciphertext_sha256(metadata)
        now = time.monotonic()
        cached = _webhook_secret_cache
        if (
            cached is not None
            and cached.version == version
            and cached.ciphertext_sha256 == ciphertext_sha256
            and now < cached.expires_at
            and cached.remaining_uses > 0
        ):
            cached.remaining_uses -= 1
            return cached.secret

        decrypted = _parameter_row(
            _ssm().get_parameter(Name=name, WithDecryption=True),
            expected_name=name,
            expected_type="SecureString",
            require_value=True,
        )
        if int(decrypted["Version"]) != version:
            _webhook_secret_cache = None
            raise RuntimeError("webhook secret parameter version changed during refresh")
        value = decrypted["Value"]
        assert isinstance(value, str)
        secret = value.encode("utf-8")
        if not MIN_WEBHOOK_SECRET_BYTES <= len(secret) <= MAX_WEBHOOK_SECRET_BYTES:
            _webhook_secret_cache = None
            raise RuntimeError("configured webhook secret is outside bounds")

        confirmed = _parameter_row(
            _ssm().get_parameter(Name=name, WithDecryption=False),
            expected_name=name,
            expected_type="SecureString",
            require_value=True,
        )
        if (
            int(confirmed["Version"]) != version
            or _secure_string_ciphertext_sha256(confirmed) != ciphertext_sha256
        ):
            _webhook_secret_cache = None
            raise RuntimeError("webhook secret parameter changed during refresh")

        _webhook_secret_cache = _WebhookSecretCache(
            secret=secret,
            version=version,
            ciphertext_sha256=ciphertext_sha256,
            expires_at=now + WEBHOOK_SECRET_CACHE_TTL_SECONDS,
            remaining_uses=WEBHOOK_SECRET_CACHE_MAX_USES - 1,
        )
        return secret


def _policy_pin() -> str:
    expected_sha = os.environ.get(POLICY_SHA_ENV, "")
    if len(expected_sha) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha):
        raise RuntimeError("deployment policy SHA-256 pin is missing or malformed")
    return expected_sha


def _load_policy(*, expected_sha: str | None = None) -> tuple[bytes, str]:
    expected_sha = _policy_pin() if expected_sha is None else expected_sha
    if expected_sha == ZERO_POLICY_SHA:
        raise RuntimeError("deployment policy is idle")
    if len(expected_sha) != 64 or any(ch not in "0123456789abcdef" for ch in expected_sha):
        raise RuntimeError("deployment policy SHA-256 pin is missing or malformed")
    name = _parameter_name(POLICY_PARAMETER_SUFFIX)
    parameter = _parameter_row(
        _ssm().get_parameter(Name=name, WithDecryption=False),
        expected_name=name,
        expected_type="String",
        require_value=True,
    )
    value = parameter["Value"]
    assert isinstance(value, str)
    payload = value.encode("utf-8")
    if not payload or len(payload) > min(MAX_POLICY_BYTES, MAX_SSM_STANDARD_VALUE_BYTES):
        raise RuntimeError("maintenance policy exceeds SSM Standard bounds")
    observed = hashlib.sha256(payload).hexdigest()
    if observed != expected_sha:
        raise RuntimeError("maintenance policy differs from deployment SHA-256 pin")
    return payload, expected_sha


def _load_public_config() -> PublicConfig:
    names = _public_parameter_names()
    response = _ssm().get_parameters(Names=list(names.values()), WithDecryption=False)
    if not isinstance(response, dict):
        raise RuntimeError("SSM public parameter response is malformed")
    invalid = response.get("InvalidParameters")
    if invalid:
        raise RuntimeError("required SSM public parameters are missing")
    rows = response.get("Parameters")
    if not isinstance(rows, list) or len(rows) != len(names):
        raise RuntimeError("SSM public parameter response is incomplete")

    by_name: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("SSM public parameter response is malformed")
        name = row.get("Name")
        value = row.get("Value")
        version = row.get("Version")
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or row.get("Type") != "String"
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version < 1
        ):
            raise RuntimeError("SSM public parameter name/value/type/version is malformed")
        if name in by_name or len(value.encode("utf-8")) > MAX_SSM_STANDARD_VALUE_BYTES:
            raise RuntimeError("SSM Standard public parameter response is duplicate or oversized")
        by_name[name] = value
    if set(by_name) != set(names.values()):
        raise RuntimeError("SSM public parameter identity set is not exact")

    app_id = _canonical_positive_int_text(by_name[names["app_id"]], "app id")
    installation_id = _positive_int(by_name[names["installation_id"]], "installation id")
    bot_login = _bounded_ascii(by_name[names["bot_login"]], "bot login", max_bytes=128)
    if not bot_login.endswith("[bot]"):
        raise RuntimeError("configured bot login is not a GitHub App bot identity")

    repository = by_name[names["repository"]]
    if repository != EXPECTED_REPOSITORY:
        raise RuntimeError("configured repository differs from reviewed repository")
    repository_id = _positive_int(by_name[names["repository_id"]], "repository id")
    if repository_id != EXPECTED_REPOSITORY_ID:
        raise RuntimeError("configured repository id differs from reviewed repository")

    return PublicConfig(
        app_id=app_id,
        installation_id=installation_id,
        repository=repository,
        repository_id=repository_id,
        bot_login=bot_login,
    )


def _load_private_key() -> str:
    name = _parameter_name(APP_SIGNING_PARAMETER_SUFFIX)
    parameter = _parameter_row(
        _ssm().get_parameter(Name=name, WithDecryption=True),
        expected_name=name,
        expected_type="SecureString",
        require_value=True,
    )
    private_key_pem = parameter["Value"]
    assert isinstance(private_key_pem, str)
    if not private_key_pem or len(private_key_pem.encode("utf-8")) > MAX_SSM_STANDARD_VALUE_BYTES:
        raise RuntimeError("configured App private key is missing or exceeds SSM Standard bounds")
    return private_key_pem


def _prefilter_authenticated_wakeup(policy: OneShotPolicy, wakeup: Wakeup) -> None:
    if policy.repository != EXPECTED_REPOSITORY or policy.repository_id != EXPECTED_REPOSITORY_ID:
        raise PermissionError("maintenance policy is not bound to the reviewed repository")
    if wakeup.repository != EXPECTED_REPOSITORY or wakeup.repository_id != EXPECTED_REPOSITORY_ID:
        raise PermissionError("webhook repository identity is not authorized")
    if wakeup.repository != policy.repository or wakeup.repository_id != policy.repository_id:
        raise PermissionError("webhook repository identity does not match active policy")
    now = datetime.now(UTC)
    if not (policy.not_before <= now < policy.expires_at):
        raise PermissionError("maintenance policy is not active")
    if wakeup.event_head_sha != policy.head_sha:
        raise PermissionError("webhook workflow head does not match active maintenance policy")


def _build_service(
    config: StaticConfig,
    *,
    policy_bytes: bytes,
    policy_sha256: str,
) -> TrustedGateService:
    table_name = os.environ.get(TABLE_ENV, "")
    if not table_name:
        raise RuntimeError("DynamoDB table name is not configured")
    token_provider = AppTokenProvider(
        app_id=config.app_id,
        installation_id=config.installation_id,
        repository=config.repository,
        private_key_pem=config.private_key_pem,
    )
    github = GitHubClient(
        token_provider=token_provider,
        installation_id=config.installation_id,
    )
    store = DynamoDeliveryStore(client=_dynamodb(), table_name=table_name)

    fd, raw_path = tempfile.mkstemp(prefix="trusted-gate-policy-", suffix=".json", dir="/tmp")
    path = Path(raw_path)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(policy_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        service = TrustedGateService(
            config=ServiceConfig(
                webhook_secret=config.webhook_secret,
                installation_id=config.installation_id,
                expected_creator_login=config.bot_login,
                policy_path=path,
                policy_sha256=policy_sha256,
            ),
            store=store,  # type: ignore[arg-type]
            github=github,
        )
    finally:
        path.unlink(missing_ok=True)
    return service


def _parameter_prefix() -> str:
    prefix = os.environ.get(CONFIG_PREFIX_ENV, "")
    if (
        not prefix
        or len(prefix.encode("utf-8")) > MAX_PARAMETER_PREFIX_BYTES
        or PARAMETER_PREFIX_RE.fullmatch(prefix) is None
        or len(prefix.split("/")) - 1 > MAX_PARAMETER_PREFIX_DEPTH
    ):
        raise RuntimeError("deployment SSM parameter prefix is missing or malformed")
    return prefix


def _parameter_name(suffix: str) -> str:
    reviewed_suffixes = {
        *STATIC_PARAMETER_SUFFIXES.values(),
        WEBHOOK_SECRET_SUFFIX,
        POLICY_PARAMETER_SUFFIX,
    }
    if suffix not in reviewed_suffixes:
        raise RuntimeError("SSM parameter suffix is not reviewed")
    return f"{_parameter_prefix()}/{suffix}"


def _public_parameter_names() -> dict[str, str]:
    return {key: _parameter_name(suffix) for key, suffix in PUBLIC_PARAMETER_SUFFIXES.items()}


def _ssm() -> Any:
    global _ssm_client
    if _ssm_client is None:
        _ssm_client = _boto3_client("ssm")
    return _ssm_client


def _dynamodb() -> Any:
    global _dynamodb_client
    if _dynamodb_client is None:
        _dynamodb_client = _boto3_client("dynamodb")
    return _dynamodb_client


def _boto3_client(service_name: str) -> Any:
    import boto3
    from botocore.config import Config

    return boto3.client(
        service_name,
        config=Config(
            connect_timeout=2,
            read_timeout=5,
            retries={"max_attempts": 2, "mode": "standard"},
            user_agent_extra="yp-ai-qa-trusted-pr-gate/1",
        ),
    )


def _positive_int(value: str, label: str) -> int:
    if not value.isdigit():
        raise RuntimeError(f"configured {label} is malformed")
    parsed = int(value)
    if parsed < 1:
        raise RuntimeError(f"configured {label} must be positive")
    return parsed


def _canonical_positive_int_text(value: str, label: str) -> str:
    parsed = _positive_int(value, label)
    if value != str(parsed):
        raise RuntimeError(f"configured {label} is not canonical")
    return value


def _bounded_ascii(value: str, label: str, *, max_bytes: int) -> str:
    if not value or not value.isascii() or len(value.encode("ascii")) > max_bytes:
        raise RuntimeError(f"configured {label} is malformed")
    return value


def _log_failure(stage: FailureStage, exc: Exception) -> None:
    LOGGER.warning(
        "trusted_gate_lambda_failure stage=%s exception=%s",
        stage,
        type(exc).__name__,
    )


def _response(status: int, payload: dict[str, Any], *, retry_after: bool = False) -> dict[str, Any]:
    headers = {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
    }
    if retry_after:
        headers["retry-after"] = "30"
    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(payload, separators=(",", ":"), sort_keys=True),
        "isBase64Encoded": False,
    }
