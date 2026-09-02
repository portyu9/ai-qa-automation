from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from ..io_safety import parse_json_object_strict, read_bytes_bounded
from .execution_env import (
    BoundedSubprocessResult,
    restricted_subprocess_env,
    run_bounded_subprocess,
)

_SANDBOX_EXECUTABLE_MAX_BYTES = 32 * 1024 * 1024
_SANDBOX_PROBE_TIMEOUT_SECONDS = 10
_SANDBOX_PROBE_OUTPUT_BYTES = 64 * 1024
_NAMESPACE_NAMES = ("mnt", "pid", "net", "user")
_BWRAP_SEARCH_PATH = "/usr/bin:/bin"
_SANDBOX_AUTHORITY_EXIT_CODE = 126
_SANDBOX_MAX_PROCESSES = 16
_SANDBOX_MAX_ADDRESS_SPACE_BYTES = 512 * 1024 * 1024
_SANDBOX_MAX_FILE_BYTES = 64 * 1024 * 1024
_SANDBOX_MAX_OPEN_FILES = 256
_SANDBOX_TMPFS_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PytestSandboxPreflight:
    ready: bool
    backend: str
    reason: str | None
    executable: str | None = None
    executable_sha256: str | None = None
    version: str | None = None
    parent_namespaces: dict[str, str] | None = None
    child_namespaces: dict[str, str] | None = None
    workspace_identity_bound: bool = False
    workspace_read_only: bool = False
    forbidden_roots_hidden: bool = False
    no_non_loopback_interfaces: bool = False
    effective_capabilities_zero: bool = False
    max_processes: int = _SANDBOX_MAX_PROCESSES
    max_address_space_bytes: int = _SANDBOX_MAX_ADDRESS_SPACE_BYTES
    max_file_bytes: int = _SANDBOX_MAX_FILE_BYTES
    max_open_files: int = _SANDBOX_MAX_OPEN_FILES
    tmpfs_bytes: int = _SANDBOX_TMPFS_BYTES

    def details(self) -> dict[str, object]:
        return {
            "backend": self.backend,
            "ready": self.ready,
            "reason": self.reason,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "version": self.version,
            "parent_namespaces": dict(self.parent_namespaces or {}),
            "child_namespaces": dict(self.child_namespaces or {}),
            "workspace_identity_bound": self.workspace_identity_bound,
            "workspace_read_only": self.workspace_read_only,
            "forbidden_roots_hidden": self.forbidden_roots_hidden,
            "no_non_loopback_interfaces": self.no_non_loopback_interfaces,
            "effective_capabilities_zero": self.effective_capabilities_zero,
            "max_processes": self.max_processes,
            "max_address_space_bytes": self.max_address_space_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_open_files": self.max_open_files,
            "tmpfs_bytes": self.tmpfs_bytes,
        }


class PytestSandbox(Protocol):
    @property
    def python_executable(self) -> Path: ...

    def preflight(self) -> PytestSandboxPreflight: ...

    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: int | float,
    ) -> tuple[PytestSandboxPreflight, BoundedSubprocessResult]: ...


class PytestSandboxUnavailable(RuntimeError):
    def __init__(self, preflight: PytestSandboxPreflight) -> None:
        self.preflight = preflight
        super().__init__(preflight.reason or "pytest sandbox is unavailable")


class PytestSandboxExecutionUnverified(RuntimeError):
    def __init__(
        self,
        preflight: PytestSandboxPreflight,
        result: BoundedSubprocessResult,
        reason: str,
    ) -> None:
        self.preflight = preflight
        self.result = result
        self.reason = reason
        super().__init__(reason)


class BubblewrapPytestSandbox:
    """Run target pytest inside a fail-closed Bubblewrap security boundary.

    The sandbox starts from Bubblewrap's empty filesystem namespace, exposes only
    the interpreter/runtime roots required to launch pytest plus the target
    workspace as a read-only mount, creates bounded private writable home/tmp
    filesystems, and unshares user/PID/network/IPC/UTS namespaces. No host root
    bind exists. Immediately before target execution, a trusted guard also applies
    per-process resource ceilings and revalidates the mounted subject/isolation.
    """

    backend_name = "bubblewrap"

    def __init__(self, workspace: Path, *, evidence_root: Path) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.evidence_root = evidence_root.expanduser().resolve()
        self._python_executable = Path(sys.executable).expanduser().resolve()

    @property
    def python_executable(self) -> Path:
        return self._python_executable

    def preflight(self) -> PytestSandboxPreflight:
        if os.name != "posix" or not sys.platform.startswith("linux"):
            return self._blocked("Bubblewrap pytest isolation requires Linux")

        with tempfile.TemporaryDirectory(prefix="aiqa-bwrap-preflight-") as host_home:
            env = restricted_subprocess_env(home=Path(host_home))
            executable = shutil.which("bwrap", path=_BWRAP_SEARCH_PATH)
            if not executable:
                return self._blocked(
                    "Bubblewrap executable is not available on the controlled PATH"
                )
            try:
                discovered_path = Path(executable)
                discovered = discovered_path.stat(follow_symlinks=False)
                if stat.S_ISLNK(discovered.st_mode) or not stat.S_ISREG(discovered.st_mode):
                    raise ValueError("Bubblewrap executable discovery is not a regular owned path")
                if not os.access(discovered_path, os.X_OK):
                    raise ValueError("Bubblewrap executable is not executable")
                executable_path = discovered_path.resolve(strict=True)
                identity_before = self._stable_regular_identity(executable_path)
                digest_before = self._hash_executable(executable_path)
            except (OSError, ValueError) as exc:
                return self._blocked(
                    f"Bubblewrap executable cannot be bound safely: {type(exc).__name__}"
                )

            if self._path_within(executable_path, self.workspace) or self._path_within(
                executable_path, self.evidence_root
            ):
                return self._blocked(
                    "Bubblewrap executable is inside an untrusted/runtime evidence root"
                )

            version_result = run_bounded_subprocess(
                [str(executable_path), "--version"],
                cwd=Path("/"),
                env=env,
                timeout_seconds=_SANDBOX_PROBE_TIMEOUT_SECONDS,
                max_output_bytes=_SANDBOX_PROBE_OUTPUT_BYTES,
            )
            if (
                version_result.timed_out
                or version_result.returncode != 0
                or version_result.stdout_truncated
                or version_result.stderr_truncated
                or version_result.stderr.strip()
            ):
                return self._blocked(
                    "Bubblewrap version probe did not complete cleanly",
                    executable=executable_path,
                    executable_sha256=digest_before,
                )
            version = version_result.stdout.strip()
            if not version.startswith("bubblewrap ") or len(version) > 100:
                return self._blocked(
                    "Bubblewrap version output is malformed",
                    executable=executable_path,
                    executable_sha256=digest_before,
                )

            try:
                parent_namespaces = self._namespace_identities()
                workspace_identity = self.workspace.stat(follow_symlinks=False)
                if not stat.S_ISDIR(workspace_identity.st_mode):
                    raise ValueError("target workspace is no longer a directory")
                probe_name = f".aiqa-sandbox-write-probe-{uuid4().hex}"
                probe_command = self._build_command(
                    executable_path,
                    [
                        str(self._python_executable),
                        "-I",
                        "-S",
                        "-c",
                        _PROBE_SCRIPT,
                        probe_name,
                        str(workspace_identity.st_dev),
                        str(workspace_identity.st_ino),
                        str(self.evidence_root),
                    ],
                )
                probe_result = run_bounded_subprocess(
                    probe_command,
                    cwd=Path("/"),
                    env=env,
                    timeout_seconds=_SANDBOX_PROBE_TIMEOUT_SECONDS,
                    max_output_bytes=_SANDBOX_PROBE_OUTPUT_BYTES,
                )
            except (OSError, ValueError) as exc:
                return self._blocked(
                    f"Bubblewrap capability probe could not start safely: {type(exc).__name__}",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                )

            if (
                probe_result.timed_out
                or probe_result.returncode != 0
                or probe_result.stdout_truncated
                or probe_result.stderr_truncated
                or probe_result.stderr.strip()
            ):
                return self._blocked(
                    "Bubblewrap capability probe did not complete cleanly",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                )
            try:
                payload = parse_json_object_strict(
                    probe_result.stdout, label="Bubblewrap capability probe"
                )
            except ValueError:
                return self._blocked(
                    "Bubblewrap capability probe returned malformed JSON",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                )
            child_namespaces = payload.get("namespaces")
            if not isinstance(child_namespaces, dict) or set(child_namespaces) != set(
                _NAMESPACE_NAMES
            ):
                return self._blocked(
                    "Bubblewrap capability probe omitted required namespace identity",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                )
            if not all(
                isinstance(key, str) and isinstance(value, str) and value
                for key, value in child_namespaces.items()
            ):
                return self._blocked(
                    "Bubblewrap capability probe returned malformed namespace identity",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                )
            normalized_child = dict(child_namespaces)
            namespace_separated = all(
                normalized_child[name] != parent_namespaces[name] for name in _NAMESPACE_NAMES
            )
            workspace_identity_bound = payload.get("workspace_identity_bound") is True
            workspace_read_only = payload.get("workspace_read_only") is True
            forbidden_roots_hidden = payload.get("forbidden_roots_hidden") is True
            no_non_loopback = payload.get("no_non_loopback_interfaces") is True
            caps_zero = payload.get("effective_capabilities_zero") is True
            parent_probe_path = self.workspace / probe_name
            if parent_probe_path.exists() or parent_probe_path.is_symlink():
                return self._blocked(
                    "Bubblewrap probe modified the host target workspace",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                    child_namespaces=normalized_child,
                )

            try:
                identity_after = self._stable_regular_identity(executable_path)
                digest_after = self._hash_executable(executable_path)
            except (OSError, ValueError):
                return self._blocked(
                    "Bubblewrap executable changed identity after capability probe",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=version,
                    parent_namespaces=parent_namespaces,
                    child_namespaces=normalized_child,
                )
            executable_stable = identity_before == identity_after and digest_before == digest_after

            ready = (
                namespace_separated
                and workspace_identity_bound
                and workspace_read_only
                and forbidden_roots_hidden
                and no_non_loopback
                and caps_zero
                and executable_stable
            )
            reason = (
                None
                if ready
                else "Bubblewrap capability proof did not establish every isolation invariant"
            )
            return PytestSandboxPreflight(
                ready=ready,
                backend=self.backend_name,
                reason=reason,
                executable=str(executable_path),
                executable_sha256=digest_after,
                version=version,
                parent_namespaces=parent_namespaces,
                child_namespaces=normalized_child,
                workspace_identity_bound=workspace_identity_bound,
                workspace_read_only=workspace_read_only,
                forbidden_roots_hidden=forbidden_roots_hidden,
                no_non_loopback_interfaces=no_non_loopback,
                effective_capabilities_zero=caps_zero,
            )

    def run(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: int | float,
    ) -> tuple[PytestSandboxPreflight, BoundedSubprocessResult]:
        preflight = self.preflight()
        if not preflight.ready or preflight.executable is None:
            raise PytestSandboxUnavailable(preflight)
        executable_path = Path(preflight.executable)
        identity_before = self._stable_regular_identity(executable_path)
        digest_before = self._hash_executable(executable_path)
        if digest_before != preflight.executable_sha256:
            raise PytestSandboxUnavailable(
                self._blocked(
                    "Bubblewrap executable changed after capability proof",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=preflight.version,
                )
            )

        execution_command = self._execution_guard_command(
            preflight,
            command,
            cpu_limit_seconds=max(1, int(float(timeout_seconds)) + 1),
        )
        with tempfile.TemporaryDirectory(prefix="aiqa-bwrap-run-") as host_home:
            host_env = restricted_subprocess_env(home=Path(host_home))
            with tempfile.TemporaryFile(mode="w+b") as status_stream:
                status_fd = status_stream.fileno()
                wrapped = self._build_command(
                    executable_path,
                    execution_command,
                    extra_env=env,
                    status_fd=status_fd,
                )
                result = run_bounded_subprocess(
                    wrapped,
                    cwd=Path("/"),
                    env=host_env,
                    timeout_seconds=timeout_seconds,
                    pass_fds=(status_fd,),
                )
                status_stream.seek(0)
                status_bytes = status_stream.read(_SANDBOX_PROBE_OUTPUT_BYTES + 1)
        if len(status_bytes) > _SANDBOX_PROBE_OUTPUT_BYTES:
            raise PytestSandboxExecutionUnverified(
                preflight,
                result,
                "Bubblewrap status evidence exceeded its deterministic byte bound",
            )
        # The status FD is untrusted-child-adjacent. It is corroboration, not sole
        # authority: extra/duplicate/malformed records only downgrade the run, while
        # the controller-observed Bubblewrap result must still match exactly.
        try:
            status_events = [
                parse_json_object_strict(line, label="Bubblewrap status event")
                for line in status_bytes.decode("utf-8").splitlines()
                if line.strip()
            ]
        except (UnicodeDecodeError, ValueError) as exc:
            raise PytestSandboxExecutionUnverified(
                preflight, result, "Bubblewrap status evidence was malformed"
            ) from exc
        child_events = [
            item
            for item in status_events
            if "child-pid" in item and type(item.get("child-pid")) is int and item["child-pid"] > 0
        ]
        if len(child_events) != 1:
            raise PytestSandboxUnavailable(
                self._blocked(
                    "Bubblewrap did not prove exactly one sandbox child started",
                    executable=executable_path,
                    executable_sha256=digest_before,
                    version=preflight.version,
                )
            )
        exit_events = [
            item
            for item in status_events
            if "exit-code" in item and type(item.get("exit-code")) is int
        ]
        if result.timed_out:
            if len(exit_events) > 1:
                raise PytestSandboxExecutionUnverified(
                    preflight, result, "Bubblewrap reported duplicate child exit status"
                )
        elif len(exit_events) != 1 or exit_events[0]["exit-code"] != result.returncode:
            raise PytestSandboxExecutionUnverified(
                preflight,
                result,
                "Bubblewrap child exit code did not match controller-observed completion",
            )

        try:
            identity_after = self._stable_regular_identity(executable_path)
            digest_after = self._hash_executable(executable_path)
        except (OSError, ValueError) as exc:
            raise PytestSandboxExecutionUnverified(
                preflight,
                result,
                "Bubblewrap executable identity was unavailable after target execution",
            ) from exc
        if identity_after != identity_before or digest_after != digest_before:
            raise PytestSandboxExecutionUnverified(
                preflight,
                result,
                "Bubblewrap executable changed identity after target execution",
            )
        if result.returncode == _SANDBOX_AUTHORITY_EXIT_CODE and not result.timed_out:
            raise PytestSandboxExecutionUnverified(
                preflight,
                result,
                "sandbox authority guard rejected target execution",
            )
        return preflight, result

    def _execution_guard_command(
        self,
        preflight: PytestSandboxPreflight,
        command: Sequence[str],
        *,
        cpu_limit_seconds: int,
    ) -> list[str]:
        if preflight.parent_namespaces is None:
            raise ValueError("sandbox preflight omitted parent namespace identity")
        expected = self.workspace.stat(follow_symlinks=False)
        if not stat.S_ISDIR(expected.st_mode):
            raise ValueError("target workspace is no longer a directory")
        guard_probe_name = f".aiqa-sandbox-run-write-probe-{uuid4().hex}"
        return [
            str(self._python_executable),
            "-I",
            "-S",
            "-c",
            _EXECUTION_GUARD_SCRIPT,
            guard_probe_name,
            str(expected.st_dev),
            str(expected.st_ino),
            str(self.evidence_root),
            *(preflight.parent_namespaces[name] for name in _NAMESPACE_NAMES),
            str(cpu_limit_seconds),
            str(_SANDBOX_MAX_PROCESSES),
            str(_SANDBOX_MAX_ADDRESS_SPACE_BYTES),
            str(_SANDBOX_MAX_FILE_BYTES),
            str(_SANDBOX_MAX_OPEN_FILES),
            "--",
            *[str(item) for item in command],
        ]

    def _build_command(
        self,
        executable: Path,
        inner_command: Sequence[str],
        *,
        extra_env: Mapping[str, str] | None = None,
        status_fd: int | None = None,
    ) -> list[str]:
        command = [
            str(executable),
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--disable-userns",
            "--assert-userns-disabled",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--dir",
            "/tmp",
            "--size",
            str(_SANDBOX_TMPFS_BYTES),
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home",
            "--size",
            str(_SANDBOX_TMPFS_BYTES),
            "--tmpfs",
            "/home",
            "--dir",
            "/home/aiqa",
        ]
        for source in self._runtime_roots():
            command.extend(["--ro-bind", str(source), str(source)])
        command.extend(
            [
                "--ro-bind",
                str(self.workspace),
                "/workspace",
                "--chdir",
                "/workspace",
                "--setenv",
                "HOME",
                "/home/aiqa",
                "--setenv",
                "USERPROFILE",
                "/home/aiqa",
                "--setenv",
                "XDG_CONFIG_HOME",
                "/home/aiqa/.config",
                "--setenv",
                "XDG_CACHE_HOME",
                "/home/aiqa/.cache",
                "--setenv",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                "1",
                "--setenv",
                "PYTHONDONTWRITEBYTECODE",
                "1",
                "--setenv",
                "PIP_CONFIG_FILE",
                "/dev/null",
                "--setenv",
                "GIT_TERMINAL_PROMPT",
                "0",
                "--setenv",
                "GIT_PAGER",
                "cat",
                "--setenv",
                "PATH",
                self._sandbox_path(),
            ]
        )
        if extra_env:
            for key in ("LANG", "LC_ALL", "LC_CTYPE"):
                value = extra_env.get(key)
                if value:
                    command.extend(["--setenv", key, str(value)])
        if status_fd is not None:
            command.extend(["--json-status-fd", str(status_fd)])
        command.extend(["--", *[str(item) for item in inner_command]])
        return command

    def _runtime_roots(self) -> tuple[Path, ...]:
        candidates = {
            self._python_executable.parent,
            self._python_executable.parent.parent,
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
        }
        for fixed in ("/usr/bin", "/bin", "/usr/lib", "/lib", "/lib64"):
            path = Path(fixed)
            if path.exists():
                candidates.add(path.resolve())
        roots: list[Path] = []
        for candidate in sorted(candidates, key=lambda item: (len(item.parts), str(item))):
            if not candidate.exists() or self._path_within(candidate, self.workspace):
                continue
            if self._path_within(candidate, self.evidence_root):
                continue
            if any(candidate == existing or existing in candidate.parents for existing in roots):
                continue
            roots.append(candidate)
        return tuple(roots)

    def _sandbox_path(self) -> str:
        entries: list[str] = []
        for candidate in (
            self._python_executable.parent,
            Path(sys.prefix).resolve() / "bin",
            Path(sys.base_prefix).resolve() / "bin",
            Path("/usr/bin"),
            Path("/bin"),
        ):
            rendered = str(candidate)
            if candidate.exists() and rendered not in entries:
                entries.append(rendered)
        return os.pathsep.join(entries)

    def _blocked(
        self,
        reason: str,
        *,
        executable: Path | None = None,
        executable_sha256: str | None = None,
        version: str | None = None,
        parent_namespaces: dict[str, str] | None = None,
        child_namespaces: dict[str, str] | None = None,
    ) -> PytestSandboxPreflight:
        return PytestSandboxPreflight(
            ready=False,
            backend=self.backend_name,
            reason=reason,
            executable=str(executable) if executable is not None else None,
            executable_sha256=executable_sha256,
            version=version,
            parent_namespaces=parent_namespaces,
            child_namespaces=child_namespaces,
        )

    @staticmethod
    def _stable_regular_identity(path: Path) -> tuple[int, int, int, int, int]:
        observed = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError("sandbox executable must remain a regular file")
        return (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
            observed.st_ctime_ns,
        )

    @staticmethod
    def _hash_executable(path: Path) -> str:
        content = read_bytes_bounded(
            path,
            max_bytes=_SANDBOX_EXECUTABLE_MAX_BYTES,
            label="Bubblewrap executable",
        )
        return f"sha256:{hashlib.sha256(content).hexdigest()}"

    @staticmethod
    def _namespace_identities() -> dict[str, str]:
        return {name: os.readlink(f"/proc/self/ns/{name}") for name in _NAMESPACE_NAMES}

    @staticmethod
    def _path_within(candidate: Path, root: Path) -> bool:
        return candidate == root or root in candidate.parents


_EXECUTION_GUARD_SCRIPT = r'''
import os
import pathlib
import resource
import socket
import sys

AUTHORITY_EXIT = 126
NAMESPACE_NAMES = ("mnt", "pid", "net", "user")
probe_name = sys.argv[1]
expected_workspace_identity = (int(sys.argv[2]), int(sys.argv[3]))
forbidden_root = pathlib.Path(sys.argv[4])
parent_namespaces = dict(zip(NAMESPACE_NAMES, sys.argv[5:9], strict=True))
cpu_seconds = int(sys.argv[9])
max_processes = int(sys.argv[10])
max_address_space = int(sys.argv[11])
max_file_bytes = int(sys.argv[12])
max_open_files = int(sys.argv[13])
if sys.argv[14] != "--":
    raise SystemExit(AUTHORITY_EXIT)
command = sys.argv[15:]
if not command:
    raise SystemExit(AUTHORITY_EXIT)
current_namespaces = {name: os.readlink(f"/proc/self/ns/{name}") for name in NAMESPACE_NAMES}
if any(current_namespaces[name] == parent_namespaces[name] for name in NAMESPACE_NAMES):
    raise SystemExit(AUTHORITY_EXIT)
workspace = pathlib.Path("/workspace")
try:
    observed_workspace = workspace.stat()
except OSError:
    raise SystemExit(AUTHORITY_EXIT)
if (observed_workspace.st_dev, observed_workspace.st_ino) != expected_workspace_identity:
    raise SystemExit(AUTHORITY_EXIT)
probe = workspace / probe_name
try:
    probe.write_text("forbidden", encoding="utf-8")
except OSError:
    pass
else:
    try:
        probe.unlink()
    finally:
        raise SystemExit(AUTHORITY_EXIT)
if forbidden_root.exists():
    raise SystemExit(AUTHORITY_EXIT)
interfaces = [name for _index, name in socket.if_nameindex()]
if any(name != "lo" for name in interfaces):
    raise SystemExit(AUTHORITY_EXIT)
cap_eff = None
with open("/proc/self/status", encoding="utf-8") as stream:
    for line in stream:
        if line.startswith("CapEff:"):
            cap_eff = int(line.split(":", 1)[1].strip(), 16)
            break
if cap_eff != 0:
    raise SystemExit(AUTHORITY_EXIT)
limits = (
    (resource.RLIMIT_CPU, cpu_seconds),
    (resource.RLIMIT_NPROC, max_processes),
    (resource.RLIMIT_AS, max_address_space),
    (resource.RLIMIT_FSIZE, max_file_bytes),
    (resource.RLIMIT_NOFILE, max_open_files),
    (resource.RLIMIT_CORE, 0),
)
try:
    for resource_id, value in limits:
        resource.setrlimit(resource_id, (value, value))
except (OSError, ValueError):
    raise SystemExit(AUTHORITY_EXIT)
os.execv(command[0], command)
'''


_PROBE_SCRIPT = r'''
import json
import os
import pathlib
import socket
import sys

probe_name = sys.argv[1]
expected_workspace_identity = (int(sys.argv[2]), int(sys.argv[3]))
forbidden_root = pathlib.Path(sys.argv[4])
namespace_names = ("mnt", "pid", "net", "user")
workspace = pathlib.Path("/workspace")
try:
    observed_workspace = workspace.stat()
except OSError:
    observed_workspace = None
workspace_identity_bound = (
    observed_workspace is not None
    and (observed_workspace.st_dev, observed_workspace.st_ino) == expected_workspace_identity
)
probe = workspace / probe_name
workspace_read_only = False
if workspace_identity_bound:
    try:
        probe.write_text("forbidden", encoding="utf-8")
    except OSError:
        workspace_read_only = True
    else:
        try:
            probe.unlink()
        except OSError:
            pass
forbidden_roots_hidden = not forbidden_root.exists()
interfaces = [name for _index, name in socket.if_nameindex()]
no_non_loopback_interfaces = all(name == "lo" for name in interfaces)
cap_eff = None
try:
    with open("/proc/self/status", encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("CapEff:"):
                cap_eff = int(line.split(":", 1)[1].strip(), 16)
                break
except OSError:
    pass
print(
    json.dumps(
        {
            "namespaces": {
                name: os.readlink(f"/proc/self/ns/{name}") for name in namespace_names
            },
            "workspace_identity_bound": workspace_identity_bound,
            "workspace_read_only": workspace_read_only,
            "forbidden_roots_hidden": forbidden_roots_hidden,
            "no_non_loopback_interfaces": no_non_loopback_interfaces,
            "effective_capabilities_zero": cap_eff == 0,
        },
        sort_keys=True,
    )
)
'''
