from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, NoReturn

import pytest

from scripts.trusted_gate_service import aws_lambda
from scripts.trusted_gate_service.core import EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_ID

SECRET = b"test-webhook-secret-with-32-bytes!!"
DELIVERY = "00000000-0000-0000-0000-000000000089"
TEST_INSTALLATION_ID = 67890
SENSITIVE_MARKERS = (
    "PRIVATE-KEY-MATERIAL",
    "WEBHOOK-SECRET-MATERIAL",
    "sha256=attacker-controlled-signature",
    "/private/deployment/path",
    "arn:private:deployment-resource",
)


def _body() -> bytes:
    return json.dumps(
        {
            "action": "completed",
            "injected_stage": "attacker-controlled-stage",
            "workflow_run": {"id": 89},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _event() -> dict[str, Any]:
    body = _body()
    signature = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return {
        "version": "2.0",
        "rawPath": "/github/webhook",
        "headers": {
            "content-type": "application/json",
            "user-agent": "GitHub-Hookshot/test",
            "x-github-delivery": DELIVERY,
            "x-github-event": "workflow_run",
            "x-hub-signature-256": signature,
        },
        "requestContext": {"http": {"method": "POST"}},
        "body": body.decode(),
        "isBase64Encoded": False,
    }


def _secret_error() -> RuntimeError:
    return RuntimeError(" | ".join(SENSITIVE_MARKERS))


def _raise_secret_error(*args: Any, **kwargs: Any) -> NoReturn:
    del args, kwargs
    raise _secret_error()


def _raiser(exc: Exception) -> Callable[..., NoReturn]:
    def raise_exception(*args: Any, **kwargs: Any) -> NoReturn:
        del args, kwargs
        raise exc

    return raise_exception


def _assert_secret_safe_failure(
    response: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
    *,
    stage: str,
    exception_name: str = "RuntimeError",
    status_code: int = 503,
    outcome: str = "INFRASTRUCTURE_FAILURE",
) -> None:
    assert response["statusCode"] == status_code
    assert json.loads(response["body"]) == {"outcome": outcome}
    assert caplog.records[-1].getMessage() == (
        f"trusted_gate_lambda_failure stage={stage} exception={exception_name}"
    )
    rendered = caplog.text + response["body"]
    assert "attacker-controlled-stage" not in caplog.text
    for marker in SENSITIVE_MARKERS:
        assert marker not in rendered


def _prepare_authenticated_policy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    policy_sha = "1" * 64
    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)
    monkeypatch.setattr(aws_lambda, "_policy_pin", lambda: policy_sha)
    monkeypatch.setattr(
        aws_lambda,
        "_load_policy",
        lambda *, expected_sha: (b"{}", expected_sha),
    )
    monkeypatch.setattr(aws_lambda.OneShotPolicy, "parse", staticmethod(lambda raw: object()))
    monkeypatch.setattr(
        aws_lambda,
        "parse_workflow_run_wakeup",
        lambda **kwargs: SimpleNamespace(installation_id=TEST_INSTALLATION_ID),
    )
    monkeypatch.setattr(aws_lambda, "_prefilter_authenticated_wakeup", lambda policy, wakeup: None)


def _public_config() -> aws_lambda.PublicConfig:
    return aws_lambda.PublicConfig(
        app_id="12345",
        installation_id=TEST_INSTALLATION_ID,
        repository=EXPECTED_REPOSITORY,
        repository_id=EXPECTED_REPOSITORY_ID,
        bot_login="trusted-pr-gate[bot]",
    )


@dataclass
class _FailingService:
    def handle_delivery(self, **kwargs: Any) -> Any:
        del kwargs
        raise _secret_error()


@pytest.mark.parametrize(
    ("stage", "static_failure_point"),
    [
        ("webhook_auth", None),
        ("policy_load", None),
        ("static_config", "public"),
        ("static_config", "signing"),
        ("service_construct", None),
        ("delivery_acquire_or_handle", None),
    ],
)
def test_handler_logs_only_fixed_stage_and_exception_class(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stage: str,
    static_failure_point: str | None,
) -> None:
    caplog.set_level(logging.WARNING, logger=aws_lambda.__name__)

    if stage == "webhook_auth":
        monkeypatch.setattr(aws_lambda, "_load_webhook_secret", _raise_secret_error)
    elif stage == "policy_load":
        monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)
        monkeypatch.setattr(aws_lambda, "_policy_pin", lambda: "1" * 64)
        monkeypatch.setattr(aws_lambda, "_load_policy", _raise_secret_error)
    else:
        _prepare_authenticated_policy_path(monkeypatch)
        if static_failure_point == "public":
            monkeypatch.setattr(aws_lambda, "_load_public_config", _raise_secret_error)
        else:
            monkeypatch.setattr(aws_lambda, "_load_public_config", _public_config)
            if static_failure_point == "signing":
                monkeypatch.setattr(aws_lambda, "_load_private_key", _raise_secret_error)
            else:
                monkeypatch.setattr(aws_lambda, "_load_private_key", lambda: "placeholder")
                if stage == "service_construct":
                    monkeypatch.setattr(aws_lambda, "_build_service", _raise_secret_error)
                else:
                    monkeypatch.setattr(
                        aws_lambda,
                        "_build_service",
                        lambda config, *, policy_bytes, policy_sha256: _FailingService(),
                    )

    response = aws_lambda.handler(_event(), object())
    _assert_secret_safe_failure(response, caplog, stage=stage)


@pytest.mark.parametrize(
    ("loader", "exc", "status_code", "outcome"),
    [
        ("public", PermissionError("WEBHOOK-SECRET-MATERIAL"), 403, "REJECTED"),
        ("signing", ValueError("PRIVATE-KEY-MATERIAL"), 400, "INVALID"),
    ],
)
def test_existing_error_mapping_is_preserved_without_message_leakage(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    loader: str,
    exc: Exception,
    status_code: int,
    outcome: str,
) -> None:
    caplog.set_level(logging.WARNING, logger=aws_lambda.__name__)
    _prepare_authenticated_policy_path(monkeypatch)
    if loader == "public":
        monkeypatch.setattr(aws_lambda, "_load_public_config", _raiser(exc))
    else:
        monkeypatch.setattr(aws_lambda, "_load_public_config", _public_config)
        monkeypatch.setattr(aws_lambda, "_load_private_key", _raiser(exc))

    response = aws_lambda.handler(_event(), object())
    _assert_secret_safe_failure(
        response,
        caplog,
        stage="static_config",
        exception_name=type(exc).__name__,
        status_code=status_code,
        outcome=outcome,
    )
