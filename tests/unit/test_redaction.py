from __future__ import annotations

import pytest

from ai_qa_automation.redaction import redact_text, sanitize


def secret_samples() -> list[str]:
    """Construct scanner-shaped fixtures at runtime without storing credential-like literals."""
    return [
        "AK" + "IA" + "1234567890ABCDEF",
        "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz123456",
        "github_" + "pat_" + "1234567890abcdefghijklmnopqrstuv",
        "sk-" + "ant-" + "abcdefghijklmnopqrstuvwxyz",
        "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234567890",
        "xox" + "b-" + "1234567890-abcdefghijklmnop",
    ]


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


def test_url_basic_auth_password_is_redacted_but_host_and_username_remain() -> None:
    text = "https://automation-user:super-secret-password@example.test/api"
    redacted = redact_text(text)

    assert "super-secret-password" not in redacted
    assert "automation-user" in redacted
    assert "example.test/api" in redacted
    assert "[REDACTED]" in redacted


def test_private_key_block_is_redacted_as_one_secret() -> None:
    begin = "-----BEGIN " + "PRIVATE KEY-----"
    end = "-----END " + "PRIVATE KEY-----"
    private_key = f"{begin}\nnot-a-real-key-material\n{end}"
    redacted = redact_text(f"before\n{private_key}\nafter")

    assert "not-a-real-key-material" not in redacted
    assert begin not in redacted
    assert "[REDACTED]" in redacted


def test_nested_values_and_sensitive_keys_are_sanitized_recursively() -> None:
    secret = "unknown-format-secret-that-still-must-not-survive"
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
    value = {
        "authorization": "Bearer abcdefghijklmnop",
        "message": "token=abcdefghijklmnop",
        "nested": ["https://user:password@example.test"],
    }
    once = sanitize(value)
    twice = sanitize(once)
    assert twice == once


def test_non_secret_text_is_preserved_exactly() -> None:
    text = "HTTP 500 from checkout service; correlation id abc-123"
    assert redact_text(text) == text
