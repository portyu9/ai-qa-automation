from __future__ import annotations

import os
import signal
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
_DRAIN_JOIN_SECONDS = 2.0
_WINDOWS_NEW_PROCESS_GROUP = 0x00000200


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
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                return
            buffer.append(chunk)
    except (OSError, ValueError):
        # The controlling thread may close a pipe after bounded join expiry to
        # prevent a descendant that inherited the descriptor from hanging the run.
        return


def _spawn_process(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> subprocess.Popen[bytes]:
    argv = [str(item) for item in command]
    if os.name == "nt":
        return subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=_WINDOWS_NEW_PROCESS_GROUP,
        )
    return subprocess.Popen(
        argv,
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Best-effort bounded termination of the validator process tree."""
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except OSError:
            if process.poll() is None:
                process.kill()
        return

    # CREATE_NEW_PROCESS_GROUP above gives Windows taskkill a stable tree root.
    # taskkill is part of supported Windows installations and is used only for
    # cleanup of the child tree created by this adapter.
    try:
        subprocess.run(  # noqa: S603 - fixed executable/arguments, no shell
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        if process.poll() is None:
            process.kill()


def run_bounded_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int | float,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> BoundedSubprocessResult:
    """Run a subprocess while draining stdout/stderr into bounded in-memory tails.

    The child receives a dedicated process group/session. At completion the adapter
    also terminates any descendants that outlived the direct child, because target
    test/load code must not leave background processes running after validation.
    """
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

    process = _spawn_process(command, cwd=cwd, env=env)
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        _terminate_process_tree(process)
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
        _terminate_process_tree(process)
        process.wait()
    else:
        # The direct validator process exited. Kill any background descendants in
        # its dedicated group before waiting for pipe EOF; otherwise an inherited
        # stdout/stderr descriptor could keep the drain threads blocked forever.
        _terminate_process_tree(process)
    finally:
        stdout_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        stderr_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        drains_stuck = stdout_thread.is_alive() or stderr_thread.is_alive()
        if drains_stuck:
            try:
                process.stdout.close()
            except OSError:
                pass
            try:
                process.stderr.close()
            except OSError:
                pass
            stdout_thread.join(timeout=_DRAIN_JOIN_SECONDS)
            stderr_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        else:
            process.stdout.close()
            process.stderr.close()
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            raise RuntimeError("subprocess output drains did not terminate after process-tree cleanup")

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
