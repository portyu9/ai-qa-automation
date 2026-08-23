from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.io_safety import read_bytes_bounded, sha256_file_bounded


def test_bounded_ingestion_rejects_symlink_subject(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    target.write_bytes(b"trusted-bytes")
    alias = tmp_path / "alias.bin"
    try:
        alias.symlink_to(target)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        read_bytes_bounded(alias, max_bytes=1024, label="subject")
    with pytest.raises(ValueError, match="symlink"):
        sha256_file_bounded(alias, max_bytes=1024, label="subject")


def test_bounded_ingestion_rejects_directory_subject(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        read_bytes_bounded(tmp_path, max_bytes=1024, label="subject")
