from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scripts.trusted_gate_service import aws_lambda
from scripts.trusted_gate_service.core import EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_ID

SECRET = b"test-webhook-secret-with-32-bytes!!"
DELIVERY = "00000000-0000-0000-0000-000000000001"
TEST_APP_ID = "12345"
TEST_INSTALLATION_ID = 67890
TEST_BOT_LOGIN = "example-trusted-gate[bot]"
TEST_PREFIX = "/private/example/trusted-gate"
BODY = json.dumps(
    {
        "action": "completed",
        "installation": {"id": TEST_INSTALLATION_ID},
        "repository": {"id": EXPECTED_REPOSITORY_ID, "full_name": EXPECTED_REPOSITORY},
        "workflow_run": {"id": 33423628422, "head_sha": "1" * 40},
    },
    separators=(",", ":"),
    sort_keys=True,
).encode()


def _signature(body: bytes = BODY) -> str:
    return "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()


def _event(
    *,
    body: bytes = BODY,
    encoded: bool = False,
    signature: str | None = None,
) -> dict[str, Any]:
    rendered = base64.b64encode(body).decode() if encoded else body.decode()
    return {
        "version": "2.0",
        "rawPath": "/github/webhook",
        "headers": {
            "content-type": "application/json",
            "user-agent": "GitHub-Hookshot/abcdef",
            "x-github-delivery": DELIVERY,
            "x-github-event": "workflow_run",
            "x-hub-signature-256": signature or _signature(body),
        },
        "requestContext": {"http": {"method": "POST"}},
        "body": rendered,
        "isBase64Encoded": encoded,
    }


def test_lambda_deployment_zip_imports_reviewed_handler(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    package_files = (
        Path("scripts/__init__.py"),
        Path("scripts/trusted_gate_service/__init__.py"),
        Path("scripts/trusted_gate_service/aws_lambda.py"),
        Path("scripts/trusted_gate_service/core.py"),
        Path("scripts/trusted_gate_service/dynamodb_store.py"),
        Path("scripts/trusted_gate_service/github.py"),
        Path("scripts/trusted_gate_service/service.py"),
        Path("scripts/trusted_gate_service/store.py"),
    )
    archive = tmp_path / "trusted-gate-lambda.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for relative in package_files:
            bundle.write(root / relative, relative.as_posix())

    command = (
        "import sys; "
        f"sys.path.insert(0, {str(archive)!r}); "
        "from scripts.trusted_gate_service.aws_lambda import handler; "
        "assert callable(handler)"
    )
    completed = subprocess.run(
        [sys.executable, "-S", "-c", command],
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_function_url_parser_preserves_raw_webhook_bytes() -> None:
    headers, body = aws_lambda._parse_function_url_event(_event(encoded=True))
    assert body == BODY
    assert headers["x-github-event"] == "workflow_run"


def test_function_url_parser_rejects_wrong_path_sender_or_wrapper_type() -> None:
    wrong_path = _event()
    wrong_path["rawPath"] = "/"
    with pytest.raises(ValueError):
        aws_lambda._parse_function_url_event(wrong_path)

    wrong_sender = _event()
    wrong_sender["headers"]["user-agent"] = "curl/8"
    with pytest.raises(PermissionError):
        aws_lambda._parse_function_url_event(wrong_sender)

    malformed_wrapper = _event()
    malformed_wrapper["isBase64Encoded"] = 0
    with pytest.raises(ValueError):
        aws_lambda._parse_function_url_event(malformed_wrapper)


def test_invalid_signature_cannot_read_private_authority_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)

    def forbidden_static_config(*, webhook_secret: bytes) -> aws_lambda.StaticConfig:
        del webhook_secret
        raise AssertionError("private App configuration must not be read before HMAC admission")

    def forbidden_policy_read() -> tuple[bytes, str]:
        raise AssertionError("policy must not be read before HMAC admission")

    monkeypatch.setattr(aws_lambda, "_load_static_config", forbidden_static_config)
    monkeypatch.setattr(aws_lambda, "_load_policy", forbidden_policy_read)
    response = aws_lambda.handler(_event(signature="sha256=" + "0" * 64), object())
    assert response["statusCode"] == 403
    assert json.loads(response["body"]) == {"outcome": "REJECTED"}


class FakeSsm:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values
        self.get_parameter_calls: list[str] = []
        self.get_parameters_calls: list[tuple[str, ...]] = []

    def get_parameters(self, *, Names: list[str], WithDecryption: bool) -> dict[str, Any]:
        assert WithDecryption is True
        self.get_parameters_calls.append(tuple(Names))
        return {
            "Parameters": [{"Name": name, "Value": self.values[name]} for name in Names],
            "InvalidParameters": [],
        }

    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        assert WithDecryption is True
        self.get_parameter_calls.append(Name)
        return {"Parameter": {"Name": Name, "Value": self.values[Name]}}


class WrongNameSsm(FakeSsm):
    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        assert WithDecryption is True
        return {"Parameter": {"Name": f"{Name}-wrong", "Value": self.values[Name]}}


def _static_values(prefix: str = TEST_PREFIX) -> dict[str, str]:
    return {
        f"{prefix}/app-id": TEST_APP_ID,
        f"{prefix}/bot-login": TEST_BOT_LOGIN,
        f"{prefix}/installation-id": str(TEST_INSTALLATION_ID),
        f"{prefix}/{aws_lambda.APP_SIGNING_PARAMETER_SUFFIX}": "private-key-placeholder",
        f"{prefix}/repository": EXPECTED_REPOSITORY,
        f"{prefix}/repository-id": str(EXPECTED_REPOSITORY_ID),
    }


def _configure_prefix(monkeypatch: pytest.MonkeyPatch, prefix: str = TEST_PREFIX) -> None:
    monkeypatch.setenv(aws_lambda.CONFIG_PREFIX_ENV, prefix)


def test_webhook_secret_read_is_isolated_from_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    hook_parameter = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({hook_parameter: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    assert aws_lambda._load_webhook_secret() == SECRET
    assert client.get_parameter_calls == [hook_parameter]
    assert client.get_parameters_calls == []


def test_static_ssm_identity_is_private_config_but_repository_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    values = _static_values()
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm(values))

    config = aws_lambda._load_static_config(webhook_secret=SECRET)
    assert config.app_id == TEST_APP_ID
    assert config.installation_id == TEST_INSTALLATION_ID
    assert config.bot_login == TEST_BOT_LOGIN

    values[f"{TEST_PREFIX}/repository-id"] = str(EXPECTED_REPOSITORY_ID + 1)
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm(values))
    with pytest.raises(RuntimeError):
        aws_lambda._load_static_config(webhook_secret=SECRET)


@pytest.mark.parametrize(
    ("suffix", "value"),
    [
        ("app-id", "00123"),
        ("bot-login", "not-a-bot"),
        ("installation-id", "0"),
    ],
)
def test_static_ssm_rejects_malformed_deployment_identity(
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    value: str,
) -> None:
    _configure_prefix(monkeypatch)
    values = _static_values()
    values[f"{TEST_PREFIX}/{suffix}"] = value
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm(values))
    with pytest.raises(RuntimeError):
        aws_lambda._load_static_config(webhook_secret=SECRET)


def test_webhook_secret_rejects_short_value(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    hook_parameter = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm({hook_parameter: "short"}))
    with pytest.raises(RuntimeError):
        aws_lambda._load_webhook_secret()


@pytest.mark.parametrize(
    "prefix",
    [
        "",
        "private/example",
        "/private//example",
        "/private/example/",
        "/private/example with space",
    ],
)
def test_parameter_prefix_is_required_and_canonical(
    monkeypatch: pytest.MonkeyPatch,
    prefix: str,
) -> None:
    if prefix:
        monkeypatch.setenv(aws_lambda.CONFIG_PREFIX_ENV, prefix)
    else:
        monkeypatch.delenv(aws_lambda.CONFIG_PREFIX_ENV, raising=False)
    with pytest.raises(RuntimeError):
        aws_lambda._parameter_prefix()


def test_policy_requires_private_parameter_prefix_and_external_sha_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    policy = b'{"policy":"authority"}'
    digest = hashlib.sha256(policy).hexdigest()
    policy_parameter = f"{TEST_PREFIX}/policy"
    monkeypatch.setattr(
        aws_lambda,
        "_ssm_client",
        FakeSsm({policy_parameter: policy.decode()}),
    )
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, digest)
    assert aws_lambda._load_policy() == (policy, digest)

    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, "0" * 64)
    with pytest.raises(RuntimeError):
        aws_lambda._load_policy()


def test_policy_parameter_identity_must_match_requested_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    policy = b'{"policy":"authority"}'
    digest = hashlib.sha256(policy).hexdigest()
    policy_parameter = f"{TEST_PREFIX}/policy"
    monkeypatch.setattr(
        aws_lambda,
        "_ssm_client",
        WrongNameSsm({policy_parameter: policy.decode()}),
    )
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, digest)
    with pytest.raises(RuntimeError):
        aws_lambda._load_policy()
