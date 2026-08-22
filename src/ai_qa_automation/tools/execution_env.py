from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Mapping, Sequence

_SAFE_INHERITED_ENV = {
    "PATH",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "CI",
}
_DEFAULT_MAX_OUTPUT_BYTES = 2_000_000
_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class BoundedSubprocessResult:
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


class _TailBuffer:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.total = 0
        self.data = bytearray()

    def append(self, chunk: bytes) -> None:
        self.total += len(chunk)
        if len(chunk) >= self.limit:
            self.data[:] = chunk[-self.limit :]
            return
        overflow = len(self.data) + len(chunk) - self.limit
        if overflow > 0:
            del self.data[:overflow]
        self.data.extend(chunk)

    @property
    def truncated(self) -> bool:
        return self.total > self.limit

    def text(self) -> str:
        rendered = bytes(self.data).decode("utf-8", errors="replace")
        if not self.truncated:
            return rendered
        return f"...[output truncated to last {self.limit} bytes]...\n{rendered}"


def _drain_stream(stream: BinaryIO, buffer: _TailBuffer) -> None:
    while True:
        chunk = stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            return
        buffer.append(chunk)


def run_bounded_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int | float,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> BoundedSubprocessResult:
    """Run a subprocess while draining stdout/stderr into bounded in-memory tails."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("timeout_seconds must be numeric")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int):
        raise ValueError("max_output_bytes must be an integer")
    if max_output_bytes < 1:
        raise ValueError("max_output_bytes must be positive")
    if not command:
        raise ValueError("subprocess command must not be empty")

    process = subprocess.Popen(
        [str(item) for item in command],
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        process.kill()
        process.wait()
        raise RuntimeError("subprocess pipes were not created")

    stdout_buffer = _TailBuffer(max_output_bytes)
    stderr_buffer = _TailBuffer(max_output_bytes)
    stdout_thread = threading.Thread(
        target=_drain_stream,
        args=(process.stdout, stdout_buffer),
        name="aiqa-stdout-drain",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_drain_stream,
        args=(process.stderr, stderr_buffer),
        name="aiqa-stderr-drain",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        process.wait(timeout=float(timeout_seconds))
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    finally:
        stdout_thread.join()
        stderr_thread.join()
        process.stdout.close()
        process.stderr.close()

    return BoundedSubprocessResult(
        returncode=int(process.returncode),
        stdout=stdout_buffer.text(),
        stderr=stderr_buffer.text(),
        stdout_truncated=stdout_buffer.truncated,
        stderr_truncated=stderr_buffer.truncated,
        timed_out=timed_out,
    )


def restricted_subprocess_env(
    *,
    home: Path,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal subprocess environment without inheriting credentials by default."""
    home = home.expanduser().resolve()
    home.mkdir(parents=True, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if key in _SAFE_INHERITED_ENV}
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "PIP_CONFIG_FILE": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
        }
    )
    if extra:
        env.update({str(key): str(value) for key, value in extra.items()})
    return env
