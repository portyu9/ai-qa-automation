from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ai_qa_automation.tools.execution_env import (
    _TailBuffer,
    resolve_executable,
    run_bounded_subprocess,
)


def test_tail_buffer_retains_only_bounded_recent_bytes() -> None:
    buffer = _TailBuffer(8)
    buffer.append(b"12345")
    buffer.append(b"67890")

    assert bytes(buffer.data) == b"34567890"
    assert buffer.truncated is True
    assert "output truncated" in buffer.text()


def test_tail_buffer_replaces_tail_when_single_chunk_exceeds_limit() -> None:
    buffer = _TailBuffer(4)
    buffer.append(b"abcdefgh")

    assert bytes(buffer.data) == b"efgh"
    assert buffer.total == 8
    assert buffer.truncated is True


def test_resolve_executable_binds_absolute_existing_file() -> None:
    resolved = Path(resolve_executable(sys.executable, env=os.environ))

    assert resolved.is_absolute()
    assert resolved.is_file()
    assert resolved.samefile(Path(sys.executable).resolve())


def test_resolve_executable_rejects_ambiguous_or_missing_commands(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        resolve_executable("relative/tool", env={"PATH": str(tmp_path)})
    with pytest.raises(FileNotFoundError):
        resolve_executable("definitely-not-an-aiqa-executable", env={"PATH": str(tmp_path)})
    with pytest.raises(FileNotFoundError):
        resolve_executable("python", env={})


@pytest.mark.skipif(os.name == "nt", reason="POSIX execute bits are not portable to Windows")
def test_resolve_executable_rejects_absolute_non_executable_file(tmp_path: Path) -> None:
    candidate = tmp_path / "not-executable"
    candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate.chmod(0o600)

    with pytest.raises(PermissionError, match="not executable"):
        resolve_executable(str(candidate), env=os.environ)


@pytest.mark.parametrize(
    ("timeout", "max_output"),
    [
        (True, 10),
        (0, 10),
        (1, True),
        (1, 0),
    ],
)
def test_bounded_subprocess_rejects_invalid_bounds(
    tmp_path: Path,
    timeout: object,
    max_output: object,
) -> None:
    with pytest.raises(ValueError):
        run_bounded_subprocess(
            [sys.executable, "-c", "print('ok')"],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=timeout,  # type: ignore[arg-type]
            max_output_bytes=max_output,  # type: ignore[arg-type]
        )


def test_bounded_subprocess_retains_bounded_output_tail(tmp_path: Path) -> None:
    result = run_bounded_subprocess(
        [sys.executable, "-c", "print('x' * 1000)"],
        cwd=tmp_path,
        env=os.environ,
        timeout_seconds=5,
        max_output_bytes=64,
    )

    assert result.returncode == 0
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) < 256
    assert result.timed_out is False
