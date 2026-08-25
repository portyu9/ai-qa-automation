from __future__ import annotations

import hashlib

import pytest

from ai_qa_automation.redaction import redact_text, sanitize


def secret_samples() -> list[str]:
    """Construct scanner-shaped fixtures at runtime without storing credential-like literals."""
    return [
        "AK" + "IA" + "1234567890ABCDEF",  # pragma: allowlist secret
        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456",  # pragma: allowlist secret
        "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv",  # pragma: allowlist secret
        "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz",  # pragma: allowlist secret
        "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234567890",  # pragma: allowlist secret
        "xox" + "b-" + "1234567890-abcdefghijklmnop",  # pragma: allowlist secret
    ]


def redacted_path(path: str) -> str:
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return f"/_redacted_path_sha256/{digest}"


def basic_auth_url(*, username: str, credential: str, suffix: str) -> str:
    """Build a test-only credential URL without storing one as a source literal."""
    return "https://" + username + ":" + credential + "@example.test" + suffix


@pytest.mark.parametrize("secret", secret_samples())
def test_known_secret_shapes_are_redacted(secret: str) -> None:
    redacted = redact_text(f"prefix {secret} suffix")
    assert secret not in redacted
    assert "[REDACTED]" in redacted


def test_authorization_header_and_bearer_token_are_redacted() -> None:
    secret = "abcdefghijklmnop"
    text = f"Authorization: Bearer {secret}; second bearer {secret}"
    redacted = redact_text(text)

    assert secret not in redacted
    assert "Authorization: Bearer [REDACTED]" in redacted


def test_url_basic_auth_and_path_are_removed_but_origin_remains() -> None:
    username = "automation-user"
    credential = "opaque-credential-value"
    text = basic_auth_url(username=username, credential=credential, suffix="/api")
    redacted = redact_text(text)

    assert credential not in redacted
    assert username not in redacted
    assert "/api" not in redacted
    assert redacted == f"https://example.test{redacted_path('/api')}"


def test_network_url_path_query_and_fragment_are_removed_even_without_sensitive_names() -> None:
    value = "opaque-value-that-must-not-persist"
    text = f"request failed at https://example.test/checkout?session={value}#client-state"

    redacted = redact_text(text)

    assert value not in redacted
    assert "client-state" not in redacted
    assert "/checkout" not in redacted
    assert redacted == f"request failed at https://example.test{redacted_path('/checkout')}"


def test_websocket_url_userinfo_path_query_and_fragment_are_removed() -> None:
    text = "wss://" + "user:" + "pass" + "@example.test/socket?cursor=opaque#fragment"

    redacted = redact_text(text)

    assert redacted == f"wss://example.test{redacted_path('/socket')}"
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "opaque" not in redacted
    assert "fragment" not in redacted
    assert "/socket" not in redacted


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("data:text/plain,opaque-payload", "data:[REDACTED]"),
        ("blob:https://example.test/opaque-object-id", "blob:[REDACTED]"),
    ],
)
def test_opaque_browser_urls_do_not_preserve_embedded_payloads(value: str, expected: str) -> None:
    assert redact_text(value) == expected


def test_network_url_trailing_prose_punctuation_is_preserved() -> None:
    text = "See https://example.test/path?opaque=value), then continue."
    expected = f"See https://example.test{redacted_path('/path')}), then continue."
    assert redact_text(text) == expected


def test_root_network_url_remains_origin_only() -> None:
    assert redact_text("https://example.test/") == "https://example.test/"


def test_already_redacted_path_marker_is_idempotent() -> None:
    value = f"https://example.test{redacted_path('/opaque-original')}"
    assert redact_text(value) == value


def test_private_key_block_is_redacted_as_one_secret() -> None:
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    private_key = f"{begin}\nnot-a-real-key-material\n{end}"
    redacted = redact_text(f"before\n{private_key}\nafter")

    assert "not-a-real-key-material" not in redacted
    assert begin not in redacted
    assert "[REDACTED]" in redacted


def test_nested_values_and_sensitive_keys_are_sanitized_recursively() -> None:
    secret = "unknown-format-secret-that-still-must-not-survive"  # pragma: allowlist secret
    safe = sanitize(
        {
            "headers": {"authorization": "Bearer abcdefghijklmnop"},
            "nested": [
                {"api_key": secret},
                ("safe", {"private-key": secret}),
            ],
            "items": ["ok"],
        }
    )

    rendered = str(safe)
    assert "abcdefghijklmnop" not in rendered
    assert secret not in rendered
    assert safe["nested"][0]["api_key"] == "[REDACTED]"
    assert safe["nested"][1][1]["private-key"] == "[REDACTED]"
    assert safe["items"] == ["ok"]


def test_sensitive_key_name_redacts_even_non_secret_looking_value() -> None:
    safe = sanitize({"password": "hello", "session_token": "123", "normal": "hello"})
    assert safe["password"] == "[REDACTED]"
    assert safe["session_token"] == "[REDACTED]"
    assert safe["normal"] == "hello"


def test_sanitization_is_idempotent() -> None:
    credential_url = basic_auth_url(
        username="runtime-user",
        credential="runtime-credential",
        suffix="/path?session=opaque",
    )
    value = {
        "authorization": "Bearer abcdefghijklmnop",
        "message": "token=abcdefghijklmnop",
        "nested": [credential_url],
    }
    once = sanitize(value)
    twice = sanitize(once)
    assert twice == once


def test_non_secret_text_is_preserved_exactly() -> None:
    text = "HTTP 500 from checkout service; correlation id abc-123"
    assert redact_text(text) == text
