from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts.trusted_gate_service import aws_lambda
from scripts.trusted_gate_service.core import EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_ID

SECRET = b"test-webhook-secret-with-32-bytes!!"
ROTATED_SECRET = b"rotated-webhook-secret-with-32-bytes"
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


def _signature(body: bytes = BODY, *, secret: bytes = SECRET) -> str:
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


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


def _policy_bytes(*, head_sha: str = "1" * 40) -> bytes:
    now = datetime.now(UTC)
    return json.dumps(
        {
            "schema_version": 1,
            "policy_id": "kms-pressure-test-policy",
            "repository": EXPECTED_REPOSITORY,
            "repository_id": EXPECTED_REPOSITORY_ID,
            "pr_number": 92,
            "head_sha": head_sha,
            "base_sha": "2" * 40,
            "merge_sha": "3" * 40,
            "protected_changes": [
                {"path": "scripts", "base_oid": "4" * 40, "subject_oid": "5" * 40}
            ],
            "not_before": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


@pytest.fixture(autouse=True)
def _reset_lambda_clients(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(aws_lambda, "_ssm_client", None)
    monkeypatch.setattr(aws_lambda, "_dynamodb_client", None)
    monkeypatch.setattr(aws_lambda, "_webhook_secret_cache", None)


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


@pytest.mark.parametrize(
    ("header", "value", "status"),
    [
        ("x-hub-signature-256", "sha256=bad", 403),
        ("x-github-event", "push", 400),
        ("x-github-delivery", "delivery with spaces", 400),
    ],
)
def test_malformed_auth_headers_are_rejected_before_secret_read(
    monkeypatch: pytest.MonkeyPatch,
    header: str,
    value: str,
    status: int,
) -> None:
    event = _event()
    event["headers"][header] = value

    def forbidden_secret_read() -> bytes:
        raise AssertionError("malformed headers must not read the webhook secret")

    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", forbidden_secret_read)
    response = aws_lambda.handler(event, object())
    assert response["statusCode"] == status


def test_invalid_signature_cannot_read_policy_or_private_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)

    def forbidden_policy_pin() -> str:
        raise AssertionError("policy must not be read before HMAC admission")

    monkeypatch.setattr(aws_lambda, "_policy_pin", forbidden_policy_pin)
    response = aws_lambda.handler(_event(signature="sha256=" + "0" * 64), object())
    assert response["statusCode"] == 403
    assert json.loads(response["body"]) == {"outcome": "REJECTED"}


def test_zero_policy_pin_blocks_after_hmac_without_other_authority_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, aws_lambda.ZERO_POLICY_SHA)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise AssertionError("idle gate must not load policy, App authority, DynamoDB, or GitHub")

    monkeypatch.setattr(aws_lambda, "_load_policy", forbidden)
    monkeypatch.setattr(aws_lambda, "_load_public_config", forbidden)
    monkeypatch.setattr(aws_lambda, "_load_private_key", forbidden)
    monkeypatch.setattr(aws_lambda, "_build_service", forbidden)
    response = aws_lambda.handler(_event(), object())
    assert response["statusCode"] == 202
    assert json.loads(response["body"]) == {"outcome": "BLOCKED"}


def test_authenticated_policy_head_mismatch_avoids_private_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy_bytes(head_sha="9" * 40)
    digest = hashlib.sha256(policy).hexdigest()
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, digest)
    monkeypatch.setattr(aws_lambda, "_load_webhook_secret", lambda: SECRET)
    monkeypatch.setattr(aws_lambda, "_load_policy", lambda *, expected_sha: (policy, expected_sha))

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise AssertionError("head mismatch must reject before App authority or service construction")

    monkeypatch.setattr(aws_lambda, "_load_public_config", forbidden)
    monkeypatch.setattr(aws_lambda, "_load_private_key", forbidden)
    monkeypatch.setattr(aws_lambda, "_build_service", forbidden)
    response = aws_lambda.handler(_event(), object())
    assert response["statusCode"] == 403
    assert json.loads(response["body"]) == {"outcome": "REJECTED"}


class FakeSsm:
    def __init__(
        self,
        values: dict[str, str],
        *,
        types: dict[str, str] | None = None,
        versions: dict[str, int] | None = None,
        ciphertexts: dict[str, str] | None = None,
    ) -> None:
        self.values = values
        self.types = types or {}
        self.versions = versions or {}
        self.ciphertexts = ciphertexts or {}
        self.get_parameter_calls: list[tuple[str, bool]] = []
        self.get_parameters_calls: list[tuple[tuple[str, ...], bool]] = []

    def _type(self, name: str) -> str:
        if name in self.types:
            return self.types[name]
        if name.endswith(f"/{aws_lambda.WEBHOOK_SECRET_SUFFIX}") or name.endswith(
            f"/{aws_lambda.APP_SIGNING_PARAMETER_SUFFIX}"
        ):
            return "SecureString"
        return "String"

    def _row(self, name: str, *, decrypt: bool) -> dict[str, Any]:
        parameter_type = self._type(name)
        value = self.values[name]
        if parameter_type == "SecureString" and not decrypt:
            value = self.ciphertexts.get(name, "ciphertext-placeholder")
        return {
            "Name": name,
            "Value": value,
            "Type": parameter_type,
            "Version": self.versions.get(name, 1),
        }

    def get_parameters(self, *, Names: list[str], WithDecryption: bool) -> dict[str, Any]:
        self.get_parameters_calls.append((tuple(Names), WithDecryption))
        return {
            "Parameters": [self._row(name, decrypt=WithDecryption) for name in Names],
            "InvalidParameters": [],
        }

    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        self.get_parameter_calls.append((Name, WithDecryption))
        return {"Parameter": self._row(Name, decrypt=WithDecryption)}


class WrongNameSsm(FakeSsm):
    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        row = self._row(Name, decrypt=WithDecryption)
        row["Name"] = f"{Name}-wrong"
        return {"Parameter": row}


class VersionRaceSsm(FakeSsm):
    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        row = self._row(Name, decrypt=WithDecryption)
        row["Version"] = 2 if WithDecryption else 1
        self.get_parameter_calls.append((Name, WithDecryption))
        return {"Parameter": row}


class CiphertextRaceSsm(FakeSsm):
    def __init__(self, values: dict[str, str]) -> None:
        super().__init__(values)
        self.metadata_reads = 0

    def get_parameter(self, *, Name: str, WithDecryption: bool) -> dict[str, Any]:
        row = self._row(Name, decrypt=WithDecryption)
        if not WithDecryption:
            self.metadata_reads += 1
            row["Value"] = "ciphertext-before" if self.metadata_reads == 1 else "ciphertext-after"
        self.get_parameter_calls.append((Name, WithDecryption))
        return {"Parameter": row}


def _public_values(prefix: str = TEST_PREFIX) -> dict[str, str]:
    return {
        f"{prefix}/app-id": TEST_APP_ID,
        f"{prefix}/bot-login": TEST_BOT_LOGIN,
        f"{prefix}/installation-id": str(TEST_INSTALLATION_ID),
        f"{prefix}/repository": EXPECTED_REPOSITORY,
        f"{prefix}/repository-id": str(EXPECTED_REPOSITORY_ID),
    }


def _static_values(prefix: str = TEST_PREFIX) -> dict[str, str]:
    return {
        **_public_values(prefix),
        f"{prefix}/{aws_lambda.APP_SIGNING_PARAMETER_SUFFIX}": "private-key-placeholder",
    }


def _configure_prefix(monkeypatch: pytest.MonkeyPatch, prefix: str = TEST_PREFIX) -> None:
    monkeypatch.setenv(aws_lambda.CONFIG_PREFIX_ENV, prefix)


def test_webhook_secret_first_read_decrypts_once(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    assert aws_lambda._load_webhook_secret() == SECRET
    assert client.get_parameter_calls == [(name, False), (name, True), (name, False)]
    assert client.get_parameters_calls == []


def test_webhook_secret_cache_reuses_unchanged_identity_without_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    assert aws_lambda._load_webhook_secret() == SECRET
    assert aws_lambda._load_webhook_secret() == SECRET
    assert client.get_parameter_calls == [
        (name, False),
        (name, True),
        (name, False),
        (name, False),
    ]


def test_webhook_secret_version_change_forces_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    assert aws_lambda._load_webhook_secret() == SECRET
    client.values[name] = ROTATED_SECRET.decode()
    client.versions[name] = 2
    client.ciphertexts[name] = "rotated-ciphertext"
    assert aws_lambda._load_webhook_secret() == ROTATED_SECRET
    assert client.get_parameter_calls.count((name, True)) == 2


def test_webhook_secret_version_race_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = VersionRaceSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    with pytest.raises(RuntimeError, match="version changed during refresh"):
        aws_lambda._load_webhook_secret()
    assert aws_lambda._webhook_secret_cache is None


def test_webhook_secret_same_version_replacement_race_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = CiphertextRaceSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    with pytest.raises(RuntimeError, match="changed during refresh"):
        aws_lambda._load_webhook_secret()
    assert aws_lambda._webhook_secret_cache is None
    assert client.get_parameter_calls == [(name, False), (name, True), (name, False)]


def test_webhook_secret_cache_use_bound_forces_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)
    monkeypatch.setattr(aws_lambda, "WEBHOOK_SECRET_CACHE_MAX_USES", 2)

    assert aws_lambda._load_webhook_secret() == SECRET
    assert aws_lambda._load_webhook_secret() == SECRET
    assert aws_lambda._load_webhook_secret() == SECRET
    assert client.get_parameter_calls.count((name, True)) == 2


def test_webhook_secret_cache_age_bound_forces_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    client = FakeSsm({name: SECRET.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)
    times = iter((100.0, 100.0 + aws_lambda.WEBHOOK_SECRET_CACHE_TTL_SECONDS + 1.0))
    monkeypatch.setattr(aws_lambda.time, "monotonic", lambda: next(times))

    assert aws_lambda._load_webhook_secret() == SECRET
    assert aws_lambda._load_webhook_secret() == SECRET
    assert client.get_parameter_calls.count((name, True)) == 2


def test_public_config_uses_plain_reads_and_excludes_private_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    values = _static_values()
    client = FakeSsm(values)
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    config = aws_lambda._load_public_config()
    assert config.app_id == TEST_APP_ID
    assert config.installation_id == TEST_INSTALLATION_ID
    assert config.bot_login == TEST_BOT_LOGIN
    assert len(client.get_parameters_calls) == 1
    names, decrypt = client.get_parameters_calls[0]
    assert decrypt is False
    assert f"{TEST_PREFIX}/{aws_lambda.APP_SIGNING_PARAMETER_SUFFIX}" not in names


def test_public_config_rejects_malformed_deployment_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    values = _public_values()
    values[f"{TEST_PREFIX}/repository-id"] = str(EXPECTED_REPOSITORY_ID + 1)
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm(values))
    with pytest.raises(RuntimeError):
        aws_lambda._load_public_config()


def test_private_key_read_is_isolated_single_decrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.APP_SIGNING_PARAMETER_SUFFIX)
    client = FakeSsm({name: "private-key-placeholder"})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)

    assert aws_lambda._load_private_key() == "private-key-placeholder"
    assert client.get_parameter_calls == [(name, True)]


def test_webhook_secret_rejects_short_value(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_prefix(monkeypatch)
    name = aws_lambda._parameter_name(aws_lambda.WEBHOOK_SECRET_SUFFIX)
    monkeypatch.setattr(aws_lambda, "_ssm_client", FakeSsm({name: "short"}))
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


def test_policy_uses_plain_string_parameter_and_external_sha_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    policy = _policy_bytes()
    digest = hashlib.sha256(policy).hexdigest()
    name = f"{TEST_PREFIX}/policy"
    client = FakeSsm({name: policy.decode()})
    monkeypatch.setattr(aws_lambda, "_ssm_client", client)
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, digest)

    assert aws_lambda._load_policy() == (policy, digest)
    assert client.get_parameter_calls == [(name, False)]

    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, aws_lambda.ZERO_POLICY_SHA)
    with pytest.raises(RuntimeError, match="idle"):
        aws_lambda._load_policy()


def test_policy_parameter_identity_must_match_requested_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_prefix(monkeypatch)
    policy = _policy_bytes()
    digest = hashlib.sha256(policy).hexdigest()
    name = f"{TEST_PREFIX}/policy"
    monkeypatch.setattr(aws_lambda, "_ssm_client", WrongNameSsm({name: policy.decode()}))
    monkeypatch.setenv(aws_lambda.POLICY_SHA_ENV, digest)
    with pytest.raises(RuntimeError):
        aws_lambda._load_policy()
