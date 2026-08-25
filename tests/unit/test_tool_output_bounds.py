from __future__ import annotations

import hashlib
import json

import pytest

from ai_qa_automation.redaction import sanitize
from ai_qa_automation.runtime.tool_output_bounds import (
    MAX_EXTERNAL_TOOL_OUTPUT_DEPTH,
    MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES,
    ToolOutputBoundsError,
    prepare_external_tool_output,
)


class Explosive:
    def __str__(self) -> str:
        raise AssertionError("untrusted output was stringified")


def test_canonical_summary_preserves_existing_hash_and_excerpt_semantics() -> None:
    response = {"z": "é", "a": [1, 2], "url": "https://example.test/path?secret=1"}
    safe = sanitize(response)
    rendered = json.dumps(safe, sort_keys=True, default=str)

    prepared, summary = prepare_external_tool_output(response)

    assert prepared == safe
    assert summary.response_hash == f"sha256:{hashlib.sha256(rendered.encode()).hexdigest()}"
    assert summary.excerpt == rendered[:12000]
    assert summary.excerpt_hash == f"sha256:{hashlib.sha256(summary.excerpt.encode()).hexdigest()}"
    assert summary.truncated is (len(rendered) > len(summary.excerpt))


def test_arbitrary_object_is_rejected_before_stringification() -> None:
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output({"value": Explosive()})
    assert caught.value.code == "value_type"


def test_raw_oversize_is_rejected() -> None:
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output({"body": "x" * (MAX_EXTERNAL_TOOL_OUTPUT_UTF8_BYTES + 1)})
    assert caught.value.code == "utf8_bytes"


def test_excessive_depth_is_rejected() -> None:
    value: object = {}
    for _ in range(MAX_EXTERNAL_TOOL_OUTPUT_DEPTH + 1):
        value = [value]
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output(value)
    assert caught.value.code == "depth"


def test_scalar_root_is_invalid_external_response() -> None:
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output("ok")
    assert caught.value.code == "root_type"


def test_unicode_surrogate_is_rejected() -> None:
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output({"body": "bad\ud800"})
    assert caught.value.code == "invalid_unicode"


def test_sanitizer_expansion_is_revalidated() -> None:
    response = {"urls": ["https://a.test/x" for _ in range(4000)]}
    with pytest.raises(ToolOutputBoundsError) as caught:
        prepare_external_tool_output(response)
    assert caught.value.code == "utf8_bytes"
    assert "sanitized external tool output" in str(caught.value)
