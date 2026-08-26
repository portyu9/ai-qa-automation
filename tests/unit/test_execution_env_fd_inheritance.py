from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from ai_qa_automation.tools.execution_env import run_bounded_subprocess


@pytest.mark.skipif(os.name == "nt", reason="pass_fds is POSIX-only")
def test_bounded_subprocess_inherits_only_explicit_descriptor(tmp_path: Path) -> None:
    read_fd, write_fd = os.pipe()
    try:
        script = (
            "import os, sys; fd=int(sys.argv[1]); "
            "os.write(1, b'open' if os.fstat(fd) else b'unreachable')"
        )
        result = run_bounded_subprocess(
            [sys.executable, "-c", script, str(read_fd)],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            pass_fds=(read_fd,),
        )
        assert result.returncode == 0
        assert result.stdout == "open"

        closed_result = run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import os, sys; fd=int(sys.argv[1]); "
                "\ntry:\n os.fstat(fd)\nexcept OSError:\n sys.exit(0)\nsys.exit(1)",
                str(read_fd),
            ],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=5,
        )
        assert closed_result.returncode == 0
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.skipif(os.name == "nt", reason="pass_fds is POSIX-only")
@pytest.mark.parametrize("pass_fds", [(True,), (-1,), (3, 3)])
def test_bounded_subprocess_rejects_invalid_pass_fds(
    tmp_path: Path,
    pass_fds: tuple[int, ...],
) -> None:
    with pytest.raises(ValueError, match="pass_fds"):
        run_bounded_subprocess(
            [sys.executable, "-c", "print('unreachable')"],
            cwd=tmp_path,
            env=os.environ,
            timeout_seconds=5,
            pass_fds=pass_fds,
        )
