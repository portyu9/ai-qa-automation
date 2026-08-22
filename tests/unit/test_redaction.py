from ai_qa_automation.redaction import redact_text, sanitize


def test_known_secret_shapes_are_redacted() -> None:
    text = "Authorization: Bearer abcdefghijklmnop and github_pat_1234567890abcdefghijklmnopqrstuv"
    redacted = redact_text(text)
    assert "abcdefghijklmnop" not in redacted
    assert "github_pat_" not in redacted


def test_nested_values_are_sanitized() -> None:
    safe = sanitize({"headers": {"authorization": "Bearer abcdefghijklmnop"}, "items": ["ok"]})
    assert "abcdefghijklmnop" not in str(safe)
