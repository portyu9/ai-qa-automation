from __future__ import annotations

import ctypes
import math
import os
import signal
import stat
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

_SAFE_INHERITED_ENV = {
    "SYSTEMROOT",
    "WINDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "CI",
}
_DEFAULT_MAX_OUTPUT_BYTES = 2_000_000
_MAX_OUTPUT_BYTES = 16_000_000
_READ_CHUNK_BYTES = 64 * 1024
_DRAIN_JOIN_SECONDS = 2.0
_WINDOWS_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_DEFAULT_PATHEXT = ".EXE"
_WINDOWS_SYSTEM_PATH_BUFFER = 32_768
_POSIX_CONTROLLER_EXECUTABLE_ROOTS = (Path("/usr/bin"), Path("/bin"))
_CONTROLLER_AUTHORITY_ENV_KEYS = frozenset({"PATH", "VIRTUAL_ENV", "PATHEXT"})


@dataclass(frozen=True)
class BoundedSubprocessResult:
    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


@dataclass(frozen=True)
class BoundedBinarySubprocessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool


@dataclass(frozen=True)
class _BoundedCapture:
    returncode: int
    stdout: bytes
    stderr: bytes
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

    def bytes(self) -> bytes:
        return bytes(self.data)

    def text(self) -> str:
        return _render_bounded_text(self.bytes(), truncated=self.truncated, limit=self.limit)


def _render_bounded_text(data: bytes, *, truncated: bool, limit: int) -> str:
    rendered = data.decode("utf-8", errors="replace")
    if not truncated:
        return rendered
    return f"...[output truncated to last {limit} bytes]...\n{rendered}"


def _windows_executable_suffixes(env: Mapping[str, str]) -> tuple[str, ...]:
    raw_pathext = env.get("PATHEXT") or _WINDOWS_DEFAULT_PATHEXT
    suffixes: list[str] = []
    for raw_suffix in raw_pathext.split(os.pathsep):
        suffix = raw_suffix.strip()
        if (
            not suffix
            or not suffix.startswith(".")
            or any(separator in suffix for separator in ("/", "\\", "\x00"))
        ):
            raise ValueError("subprocess PATHEXT contains an invalid executable suffix")
        folded = suffix.casefold()
        if folded not in {item.casefold() for item in suffixes}:
            suffixes.append(suffix)
    if not suffixes:
        raise ValueError("subprocess PATHEXT must contain at least one executable suffix")
    return tuple(suffixes)


def _assert_executable_file(path: Path, *, env: Mapping[str, str]) -> None:
    if os.name == "nt":
        allowed_suffixes = {suffix.casefold() for suffix in _windows_executable_suffixes(env)}
        if path.suffix.casefold() not in allowed_suffixes:
            raise PermissionError(
                f"subprocess executable has an unsupported Windows suffix: {path}"
            )
        return
    if not os.access(path, os.X_OK):
        raise PermissionError(f"subprocess executable is not executable: {path}")


def _path_within(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _windows_system_directory() -> Path | None:
    """Read the Windows system executable directory from the OS, never environment."""
    if os.name != "nt":
        return None
    loader = getattr(ctypes, "windll", None)
    if loader is None:
        return None
    try:
        buffer = ctypes.create_unicode_buffer(_WINDOWS_SYSTEM_PATH_BUFFER)
        length = int(loader.kernel32.GetSystemDirectoryW(buffer, len(buffer)))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    if length <= 0 or length >= len(buffer):
        return None
    system_directory = Path(buffer.value)
    if not system_directory.is_absolute():
        return None
    return system_directory


def _controller_executable_candidates() -> tuple[Path, ...]:
    if os.name != "nt":
        return _POSIX_CONTROLLER_EXECUTABLE_ROOTS

    system_directory = _windows_system_directory()
    if system_directory is None:
        return ()
    windows_root = system_directory.parent
    candidates: list[Path] = [system_directory]
    if windows_root.drive:
        program_files = Path(f"{windows_root.drive}\\Program Files")
        candidates.extend((program_files / "Git" / "cmd", program_files / "Git" / "bin"))
    return tuple(candidates)


def _assert_controller_root_trusted(root: Path) -> None:
    """Reject mutable POSIX executable roots before they can become controller authority."""
    if os.name == "nt":
        # Windows candidates originate from GetSystemDirectoryW plus fixed Program Files
        # locations on that OS-selected drive. ACL integrity remains a deployment/OS
        # prerequisite rather than a permission-bit claim this adapter cannot prove.
        return
    observed = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(observed.st_mode):
        raise PermissionError(f"controller executable root is not a directory: {root}")
    if observed.st_uid != 0:
        raise PermissionError(f"controller executable root is not root-owned: {root}")
    if observed.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PermissionError(f"controller executable root is group/world writable: {root}")


def controller_executable_search_path() -> str:
    """Return deployment-owned search roots for host/controller executables.

    The path is derived independently of ambient PATH/VIRTUAL_ENV. Missing candidate
    roots are ignored, aliases are resolved, and an empty result fails closed. POSIX
    roots must additionally be root-owned and not group/world writable. Windows system
    identity comes from GetSystemDirectoryW instead of mutable environment variables.
    """
    roots: list[Path] = []
    for candidate in _controller_executable_candidates():
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if not resolved.is_dir() or resolved in roots:
            continue
        _assert_controller_root_trusted(resolved)
        roots.append(resolved)
    if not roots:
        raise RuntimeError("no trusted controller executable roots are available")
    return os.pathsep.join(str(root) for root in roots)


def _controlled_executable_roots(env: Mapping[str, str]) -> tuple[Path, ...]:
    search_path = env.get("PATH")
    if not search_path:
        raise FileNotFoundError("subprocess executable cannot be resolved without PATH")

    roots: list[Path] = []
    for raw_root in search_path.split(os.pathsep):
        if not raw_root:
            raise ValueError("subprocess PATH must not contain empty entries")
        candidate = Path(raw_root)
        if not candidate.is_absolute():
            raise ValueError("subprocess PATH entries must be absolute trusted roots")
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError(f"subprocess PATH root does not exist: {candidate}") from exc
        if not resolved.is_dir():
            raise NotADirectoryError(f"subprocess PATH root is not a directory: {resolved}")
        if resolved not in roots:
            roots.append(resolved)
    if not roots:
        raise FileNotFoundError(
            "subprocess executable cannot be resolved without trusted PATH roots"
        )
    return tuple(roots)


def _resolve_current_interpreter(executable: str, *, env: Mapping[str, str]) -> str | None:
    """Bind re-execution to the exact interpreter already running the controller.

    This exception authorizes only the canonical current interpreter file. It does not
    add the interpreter's directory to executable-search authority and therefore cannot
    be used to select sibling tools from a virtual environment or hosted tool cache.
    """
    candidate = Path(executable)
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        current = Path(sys.executable).resolve(strict=True)
    except OSError:
        return None
    if resolved != current:
        return None
    if not resolved.is_file():
        raise FileNotFoundError(f"current controller interpreter is not a regular file: {resolved}")
    validation_env = env if os.name != "nt" else {"PATHEXT": _WINDOWS_DEFAULT_PATHEXT}
    _assert_executable_file(resolved, env=validation_env)
    return str(resolved)


def _candidate_executable_names(raw: str, *, env: Mapping[str, str]) -> tuple[str, ...]:
    if os.name != "nt":
        return (raw,)
    suffixes = _windows_executable_suffixes(env)
    if Path(raw).suffix:
        return (raw,)
    return tuple(f"{raw}{suffix}" for suffix in suffixes)


def _discover_executable(
    raw: str,
    *,
    roots: Sequence[Path],
    env: Mapping[str, str],
) -> Path:
    """Resolve a bare name without consulting process-global PATH or PATHEXT."""
    for root in roots:
        for name in _candidate_executable_names(raw, env=env):
            candidate = root / name
            try:
                resolved = candidate.resolve(strict=True)
            except OSError:
                continue
            if not resolved.is_file():
                raise FileNotFoundError(f"subprocess executable is not a regular file: {resolved}")
            return resolved
    raise FileNotFoundError(f"subprocess executable was not found on the controlled PATH: {raw}")


def resolve_executable(executable: str, *, env: Mapping[str, str]) -> str:
    """Resolve a subprocess executable inside explicit controller authority.

    The exact interpreter already running the controller may be re-executed by canonical
    absolute path without turning its parent directory into search authority. Every other
    executable uses PATH as an explicit authority-root list: entries must be non-empty,
    absolute, and existing; named tools resolve only through those roots; other absolute
    paths must remain inside them. Process-global PATH/PATHEXT never participates.
    """
    raw = str(executable).strip()
    if not raw or "\x00" in raw:
        raise ValueError("subprocess executable must be a non-empty path or command name")

    current_interpreter = _resolve_current_interpreter(raw, env=env)
    if current_interpreter is not None:
        return current_interpreter

    roots = _controlled_executable_roots(env)
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError(f"subprocess executable was not found: {raw}") from exc
    else:
        if candidate.parent != Path():
            raise ValueError(
                "relative subprocess executable paths with directory components are forbidden"
            )
        resolved = _discover_executable(raw, roots=roots, env=env)

    if not resolved.is_file():
        raise FileNotFoundError(f"subprocess executable is not a regular file: {resolved}")
    if not any(_path_within(resolved, root) for root in roots):
        raise PermissionError(
            f"subprocess executable resolved outside controlled PATH authority roots: {resolved}"
        )
    _assert_executable_file(resolved, env=env)
    return str(resolved)


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
    pass_fds: Sequence[int] = (),
) -> subprocess.Popen[bytes]:
    argv = [str(item) for item in command]
    argv[0] = resolve_executable(argv[0], env=env)
    inherited_fds = tuple(pass_fds)
    if any(type(fd) is not int or fd < 0 for fd in inherited_fds) or len(set(inherited_fds)) != len(
        inherited_fds
    ):
        raise ValueError("pass_fds must contain unique non-negative integer descriptors")
    if os.name == "nt":
        if inherited_fds:
            raise ValueError("explicit descriptor inheritance is unsupported on Windows")
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
        pass_fds=inherited_fds,
    )


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    env: Mapping[str, str],
) -> None:
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
    # Resolve taskkill under the same explicit executable authority as the child;
    # cleanup must never fall back to partial-path ambient process execution.
    try:
        taskkill = resolve_executable("taskkill", env=env)
        cleanup = subprocess.run(
            [taskkill, "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env=dict(env),
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        cleanup = None
    if (cleanup is None or cleanup.returncode != 0) and process.poll() is None:
        process.kill()


def _validate_timeout(timeout_seconds: int | float) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ValueError("timeout_seconds must be a positive finite number")


def _validate_output_bound(value: int, *, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_OUTPUT_BYTES:
        raise ValueError(f"{name} must be an integer between 1 and {_MAX_OUTPUT_BYTES}")


def _run_bounded_capture(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int | float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    pass_fds: Sequence[int] = (),
) -> _BoundedCapture:
    _validate_timeout(timeout_seconds)
    _validate_output_bound(max_stdout_bytes, name="max_stdout_bytes")
    _validate_output_bound(max_stderr_bytes, name="max_stderr_bytes")
    if not command:
        raise ValueError("subprocess command must not be empty")

    process = _spawn_process(command, cwd=cwd, env=env, pass_fds=pass_fds)
    if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
        _terminate_process_tree(process, env=env)
        process.wait()
        raise RuntimeError("subprocess pipes were not created")

    stdout_buffer = _TailBuffer(max_stdout_bytes)
    stderr_buffer = _TailBuffer(max_stderr_bytes)
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
        _terminate_process_tree(process, env=env)
        process.wait()
    else:
        # The direct validator process exited. Clean up any background descendants
        # before waiting for pipe EOF; otherwise an inherited descriptor can keep
        # the drain threads blocked after the validator itself has finished.
        _terminate_process_tree(process, env=env)
    finally:
        stdout_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        stderr_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        drains_stuck = stdout_thread.is_alive() or stderr_thread.is_alive()
        if drains_stuck:
            with suppress(OSError):
                process.stdout.close()
            with suppress(OSError):
                process.stderr.close()
            stdout_thread.join(timeout=_DRAIN_JOIN_SECONDS)
            stderr_thread.join(timeout=_DRAIN_JOIN_SECONDS)
        else:
            process.stdout.close()
            process.stderr.close()
        if stdout_thread.is_alive() or stderr_thread.is_alive():
            raise RuntimeError(
                "subprocess output drains did not terminate after process-tree cleanup"
            )

    if process.returncode is None:  # pragma: no cover - wait() contract
        raise RuntimeError("subprocess ended without a return code")
    return _BoundedCapture(
        returncode=process.returncode,
        stdout=stdout_buffer.bytes(),
        stderr=stderr_buffer.bytes(),
        stdout_truncated=stdout_buffer.truncated,
        stderr_truncated=stderr_buffer.truncated,
        timed_out=timed_out,
    )


def run_bounded_binary_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int | float,
    max_stdout_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    max_stderr_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    pass_fds: Sequence[int] = (),
) -> BoundedBinarySubprocessResult:
    """Run a subprocess with exact bounded byte tails for stdout and stderr.

    Streams are drained concurrently even after either retention limit is exceeded,
    so the child cannot block on a full pipe while in-memory capture remains bounded.
    Callers that require complete exact output must fail closed when a truncation flag
    is set.
    """
    captured = _run_bounded_capture(
        command,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        pass_fds=pass_fds,
    )
    return BoundedBinarySubprocessResult(
        returncode=captured.returncode,
        stdout=captured.stdout,
        stderr=captured.stderr,
        stdout_truncated=captured.stdout_truncated,
        stderr_truncated=captured.stderr_truncated,
        timed_out=captured.timed_out,
    )


def run_bounded_subprocess(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int | float,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    pass_fds: Sequence[int] = (),
) -> BoundedSubprocessResult:
    """Run a subprocess while draining stdout/stderr into bounded in-memory tails.

    The child receives a dedicated process group/session. At completion the adapter
    attempts to terminate descendants that outlived the direct child, because target
    test/load code must not keep background execution attached to validation.
    """
    _validate_output_bound(max_output_bytes, name="max_output_bytes")
    captured = _run_bounded_capture(
        command,
        cwd=cwd,
        env=env,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_output_bytes,
        max_stderr_bytes=max_output_bytes,
        pass_fds=pass_fds,
    )
    return BoundedSubprocessResult(
        returncode=captured.returncode,
        stdout=_render_bounded_text(
            captured.stdout,
            truncated=captured.stdout_truncated,
            limit=max_output_bytes,
        ),
        stderr=_render_bounded_text(
            captured.stderr,
            truncated=captured.stderr_truncated,
            limit=max_output_bytes,
        ),
        stdout_truncated=captured.stdout_truncated,
        stderr_truncated=captured.stderr_truncated,
        timed_out=captured.timed_out,
    )


def restricted_subprocess_env(
    *,
    home: Path,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal environment with explicit controller executable authority."""
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
            "PATH": controller_executable_search_path(),
        }
    )
    if os.name == "nt":
        env["PATHEXT"] = _WINDOWS_DEFAULT_PATHEXT
    if extra:
        rendered = {str(key): str(value) for key, value in extra.items()}
        authority_overrides = {
            key for key in rendered if key.upper() in _CONTROLLER_AUTHORITY_ENV_KEYS
        }
        if authority_overrides:
            names = ", ".join(sorted(authority_overrides))
            raise ValueError(
                f"restricted subprocess environment cannot override executable authority: {names}"
            )
        env.update(rendered)
    return env
