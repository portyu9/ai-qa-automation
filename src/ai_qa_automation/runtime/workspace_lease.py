from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
import stat
from contextlib import AbstractContextManager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from ..io_safety import fsync_directory, parse_json_object_strict


class _MSVCRTLocking(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, fd: int, mode: int, nbytes: int) -> None: ...


def _load_msvcrt() -> _MSVCRTLocking:
    return cast(_MSVCRTLocking, importlib.import_module("msvcrt"))


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


_MAX_LEASE_METADATA_BYTES = 64_000


class WorkspaceBusyError(RuntimeError):
    """Raised when another agent process already holds the target-workspace lease."""


class WorkspaceLease(AbstractContextManager["WorkspaceLease"]):
    """Cross-process workspace lease stored outside the untrusted target repository."""

    def __init__(self, artifact_root: Path, workspace: Path, run_id: str) -> None:
        self.artifact_root = artifact_root.expanduser().resolve()
        self.workspace = workspace.expanduser().resolve()
        self.run_id = run_id
        key = hashlib.sha256(str(self.workspace).encode("utf-8")).hexdigest()[:24]
        lease_root = self.artifact_root / ".leases"
        if lease_root.is_symlink():
            raise OSError("workspace lease directory is a symlink and has ambiguous ownership")
        lease_root_existed = lease_root.exists()
        lease_root.mkdir(parents=True, exist_ok=True)
        if not lease_root_existed:
            fsync_directory(self.artifact_root)
        self.path = lease_root / f"{key}.lock"
        if self.path.is_symlink():
            raise OSError("workspace lease file is a symlink and has ambiguous ownership")
        self.lease_id = f"lease-{uuid4().hex[:16]}"
        self._stream: Any | None = None
        self.previous_metadata: dict[str, Any] | None = None

    def _supports_descriptor_relative_lease_open(self) -> bool:
        return bool(
            os.name != "nt"
            and getattr(os, "O_DIRECTORY", 0)
            and getattr(os, "O_NOFOLLOW", 0)
            and os.open in os.supports_dir_fd
            and os.stat in os.supports_dir_fd
        )

    def _open_owned_stream(self) -> tuple[Any, int | None]:
        lease_root = self.path.parent
        if lease_root.is_symlink() or self.path.is_symlink():
            raise OSError("workspace lease path has ambiguous symlink ownership")
        flags = os.O_RDWR | os.O_CREAT
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow

        if self._supports_descriptor_relative_lease_open():
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(lease_root, directory_flags)
            try:
                opened_directory = os.fstat(directory_fd)
                current_directory = lease_root.stat(follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened_directory.st_mode)
                    or not stat.S_ISDIR(current_directory.st_mode)
                    or _identity(opened_directory) != _identity(current_directory)
                ):
                    raise OSError("workspace lease directory changed identity during lock open")

                fd = os.open(self.path.name, flags, 0o600, dir_fd=directory_fd)
                try:
                    opened_file = os.fstat(fd)
                    current_file = os.stat(
                        self.path.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        not stat.S_ISREG(opened_file.st_mode)
                        or not stat.S_ISREG(current_file.st_mode)
                        or _identity(opened_file) != _identity(current_file)
                    ):
                        raise OSError("workspace lease file changed identity during lock open")
                    self._revalidate_lease_root(directory_fd)
                    return os.fdopen(fd, "r+b"), directory_fd
                except Exception:
                    os.close(fd)
                    raise
            except Exception:
                os.close(directory_fd)
                raise

        # Windows and other platforms without descriptor-relative no-follow opens
        # retain a post-open identity check rather than trusting pathname preflight.
        before_directory = lease_root.stat(follow_symlinks=False)
        fd = os.open(self.path, flags, 0o600)
        try:
            opened_file = os.fstat(fd)
            current_file = self.path.stat(follow_symlinks=False)
            after_directory = lease_root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(before_directory.st_mode)
                or not stat.S_ISDIR(after_directory.st_mode)
                or _identity(before_directory) != _identity(after_directory)
            ):
                raise OSError("workspace lease directory changed identity during lock open")
            if (
                not stat.S_ISREG(opened_file.st_mode)
                or not stat.S_ISREG(current_file.st_mode)
                or _identity(opened_file) != _identity(current_file)
            ):
                raise OSError("workspace lease file changed identity during lock open")
            return os.fdopen(fd, "r+b"), None
        except Exception:
            os.close(fd)
            raise

    def _revalidate_lease_root(self, directory_fd: int | None) -> None:
        lease_root = self.path.parent
        if directory_fd is None:
            if lease_root.is_symlink() or not lease_root.is_dir():
                raise OSError("workspace lease directory changed identity during lease acquisition")
            return
        opened_directory = os.fstat(directory_fd)
        current_directory = lease_root.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or not stat.S_ISDIR(current_directory.st_mode)
            or _identity(opened_directory) != _identity(current_directory)
        ):
            raise OSError("workspace lease directory changed identity during lease acquisition")

    def _parse_previous_metadata(self, raw: bytes) -> dict[str, Any] | None:
        normalized = raw.strip().strip(b"\0")
        if not normalized:
            return None
        try:
            decoded = normalized.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OSError(
                "workspace lease metadata is not valid UTF-8; manual review is required"
            ) from exc
        try:
            previous = parse_json_object_strict(decoded, label="workspace lease metadata")
        except json.JSONDecodeError as exc:
            raise OSError("workspace lease metadata is corrupt; manual review is required") from exc
        except ValueError as exc:
            if "root must be a JSON object" in str(exc):
                raise OSError("workspace lease metadata root must be an object") from exc
            raise OSError(
                "workspace lease metadata is corrupt or ambiguous; manual review is required"
            ) from exc

        previous_workspace = previous.get("workspace")
        previous_run_id = previous.get("run_id")
        previous_lease_id = previous.get("lease_id")
        if not isinstance(previous_workspace, str):
            raise OSError("workspace lease workspace identity must be a string")
        if previous_workspace != str(self.workspace):
            raise OSError("workspace lease metadata is bound to a different workspace")
        if not isinstance(previous_run_id, str) or not previous_run_id.strip():
            raise OSError("workspace lease run_id must be a non-empty string")
        if not isinstance(previous_lease_id, str) or not previous_lease_id.strip():
            raise OSError("workspace lease lease_id must be a non-empty string")
        return previous

    def acquire(self) -> WorkspaceLease:
        stream, directory_fd = self._open_owned_stream()
        locked = False
        try:
            self._lock_stream(stream)
            locked = True
            self._revalidate_lease_root(directory_fd)
            stream.seek(0)
            raw = stream.read(_MAX_LEASE_METADATA_BYTES + 1)
            if len(raw) > _MAX_LEASE_METADATA_BYTES:
                raise OSError("workspace lease metadata exceeds bounded ingestion limit")
            self.previous_metadata = self._parse_previous_metadata(raw)

            metadata = {
                "lease_id": self.lease_id,
                "run_id": self.run_id,
                "workspace": str(self.workspace),
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
                "acquired_at": datetime.now(UTC).isoformat(),
            }
            rendered = json.dumps(metadata, sort_keys=True).encode("utf-8")
            if len(rendered) > _MAX_LEASE_METADATA_BYTES:
                raise OSError("workspace lease metadata exceeds persistence limit")
            stream.seek(0)
            stream.truncate(0)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
            if directory_fd is not None:
                os.fsync(directory_fd)
            else:
                fsync_directory(self.path.parent)
            self._revalidate_lease_root(directory_fd)
            self._stream = stream
            return self
        except Exception:
            if locked:
                with suppress(OSError):
                    self._unlock_stream(stream)
            stream.close()
            raise
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def release(self) -> None:
        if self._stream is None:
            return
        try:
            self._unlock_stream(self._stream)
        finally:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> WorkspaceLease:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()

    @staticmethod
    def _lock_stream(stream: Any) -> None:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows path
            msvcrt = _load_msvcrt()

            try:
                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise WorkspaceBusyError("target workspace is already leased") from exc
        else:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise WorkspaceBusyError("target workspace is already leased") from exc

    @staticmethod
    def _unlock_stream(stream: Any) -> None:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows path
            msvcrt = _load_msvcrt()

            stream.seek(0)
            with suppress(OSError):
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
