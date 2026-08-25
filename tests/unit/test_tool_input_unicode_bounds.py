from __future__ import annotations

import pytest

from ai_qa_automation.runtime.tool_input_bounds import (
    ToolInputBoundsError,
    validate_tool_request,
)


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("bad\ud800", {}),
        ("tool", {"value": "bad\ud800"}),
        ("tool", {"bad\ud800": "value"}),
    ],
)
def test_unicode_surrogates_are_rejected_by_utf8_boundary(
    tool_name: str,
    tool_input: dict[str, object],
) -> None:
    with pytest.raises(ToolInputBoundsError) as caught:
        validate_tool_request(tool_name, tool_input)

    assert caught.value.code == "invalid_unicode"
    assert "Unicode surrogate" in str(caught.value)
