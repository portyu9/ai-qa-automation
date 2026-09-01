from __future__ import annotations

import base64

import pytest

from scripts.trusted_gate_service.github import (
    GitHubProtocolError,
    _decode_github_contents_base64_utf8,
)


def _wrapped(payload: bytes, *, width: int = 8) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return "\n".join(encoded[index : index + width] for index in range(0, len(encoded), width)) + "\n"


def test_github_line_wrapped_base64_is_strictly_admitted() -> None:
    raw = b"name: CI\non: pull_request\n"
    assert _decode_github_contents_base64_utf8(_wrapped(raw)) == raw.decode("utf-8")


def test_unwrapped_canonical_base64_is_admitted() -> None:
    raw = b"permissions:\n  contents: read\n"
    encoded = base64.b64encode(raw).decode("ascii")
    assert _decode_github_contents_base64_utf8(encoded) == raw.decode("utf-8")


@pytest.mark.parametrize(
    "encoded",
    [
        "YQ==\r\n",
        "YQ ==",
        "YQ\t==",
        "YQ==\n\n",
        "YQ==\n\nYg==",
        "YQ==!",
        "YQ===",
        "éQ==",
    ],
)
def test_noncanonical_github_base64_is_rejected(encoded: str) -> None:
    with pytest.raises(GitHubProtocolError, match="canonical base64 UTF-8"):
        _decode_github_contents_base64_utf8(encoded)


def test_base64_decoding_to_invalid_utf8_is_rejected() -> None:
    encoded = base64.b64encode(b"\xff").decode("ascii")
    with pytest.raises(GitHubProtocolError, match="canonical base64 UTF-8"):
        _decode_github_contents_base64_utf8(encoded)
