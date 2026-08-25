from __future__ import annotations

MAX_OBJECTIVE_UTF8_BYTES = 64_000


class ObjectiveBoundsError(ValueError):
    """Raised when an operator objective violates the runtime ingestion contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_objective(
    value: object,
    *,
    max_utf8_bytes: int = MAX_OBJECTIVE_UTF8_BYTES,
) -> str:
    """Validate an objective before state persistence or provider prompt construction."""

    if type(max_utf8_bytes) is not int or max_utf8_bytes < 1:
        raise ValueError("max_utf8_bytes must be a positive integer")
    if type(value) is not str:
        raise ObjectiveBoundsError("objective_type", "objective must be an exact string")

    total_bytes = 0
    has_non_whitespace = False
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ObjectiveBoundsError(
                "objective_unicode",
                "objective contains a Unicode surrogate outside the UTF-8 contract",
            )
        if codepoint <= 0x7F:
            total_bytes += 1
        elif codepoint <= 0x7FF:
            total_bytes += 2
        elif codepoint <= 0xFFFF:
            total_bytes += 3
        else:
            total_bytes += 4
        if total_bytes > max_utf8_bytes:
            raise ObjectiveBoundsError(
                "objective_bytes",
                "objective exceeds the deterministic UTF-8 byte limit",
            )
        if not character.isspace():
            has_non_whitespace = True

    if not has_non_whitespace:
        raise ObjectiveBoundsError(
            "objective_empty",
            "objective must contain at least one non-whitespace character",
        )
    return value
