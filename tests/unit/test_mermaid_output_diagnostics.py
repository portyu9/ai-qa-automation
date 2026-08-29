from __future__ import annotations

from pathlib import Path

import pytest

import scripts.mermaid_output as mermaid_output


def test_missing_rendered_markdown_reports_only_bounded_output_shape(tmp_path: Path) -> None:
    secret_named_dir = tmp_path / "secret-token-value"
    secret_named_dir.mkdir()

    with pytest.raises(RuntimeError) as captured:
        mermaid_output._validate_rendered_outputs(
            tmp_path,
            Path("rendered.md"),
            expected_count=1,
        )

    message = str(captured.value)
    assert "output shape:" in message
    assert "entries=1" in message
    assert "directories=1" in message
    assert "expected_markdown=False" in message
    assert "expected_svgs=0" in message
    assert "secret-token-value" not in message
