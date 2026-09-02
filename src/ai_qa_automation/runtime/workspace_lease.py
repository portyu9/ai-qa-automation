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

from ..fs_authority import descriptor_relative_authority_supported, pin_directory_identity
from ..io_safety import fsync_directory, parse_json_object_strict
from ..tools.subprocess_subject import (
    bind_active_workspace_authority,
    clear_active_workspace_authority,
)


class _MSVCRTLocking(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, fd: int, mode: int, nbytes: int) -> None: ...


def _load_msvcrt() -> _MSVCRTLocking:
    return cast(_MSVCRTLocking, importlib.import_module("msvcrt"))


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


_MAX_LEASE_METADATA_BYTES = 64_000
_DESCRIPTOR_RELATIVE_LEASE_OPEN_SUPPORTED = bool(
    os.name != "nt"
    and getattr(os, "O_DIRECTORY", 0)
    and getattr(os, "O_NOFOLLOW", 0)
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
)


class WorkspaceBusyError(RuntimeError):
    """Raised when another agent process already holds the target-workspace lease."""


class WorkspaceLease(AbstractContextManager["WorkspaceLease"]):
    """Cross-process workspace lease stored outside the untrusted target repository."""

    def __init__(
        self,
        artifact_root: Path,
        workspace: Path,
        run_id: str,
        *,
        run_root_identity: tuple[int, int] | None = None,
    ) -> None:
        self.artifact_root = artifact_root.expanduser().resolve()
        self.workspace = workspace.expanduser().resolve()
        self.run_id = run_id
        self.run_root = self.artifact_root / run_id
        self._run_root_identity = run_root_identity
        self._workspace_root_identity = (
            pin_directory_identity(self.workspace, label="target workspace")
            if descriptor_relative_authority_supported()
            else None
        )
        key = hashlib.sha256(str(self.workspace).encode("utf-8")).hexdigest()[:24]
        lease_root = self.artifact_root / ".leases"
        if lease_root.is_symlink():
            raise OSError("workspace lease directory is a symlink and has ambiguous ownership")
        lease_root_existed = lease_root.exists()
        lease_root.mkdir(parents=True, exist_ok=True)
        if not lease_root_existed:
            fsync_directory(self.artifact_root)
        lease_root_status = lease_root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(lease_root_status.st_mode):
            raise OSError("workspace lease directory does not have regular directory ownership")
        self._lease_root_identity = _identity(lease_root_status)
        self.path = lease_root / f"{key}.lock"
        if self.path.is_symlink():
            raise OSError("workspace lease file is a symlink and has ambiguous ownership")
        self.lease_id = f"lease-{uuid4().hex[:16]}"
        self._stream: Any | None = None
        self._workspace_lock_fd: int | None = None
        self._authority_bound = False
        self.previous_metadata: dict[str, Any] | None = None

    @property
    def run_root_identity(self) -> tuple[int, int] | None:
        """Return the run-persistence identity recorded by this lease."""

        return self._run_root_identity

    @property
    def workspace_root_identity(self) -> tuple[int, int] | None:
        """Return the target workspace identity this lease instance was created for."""

        return self._workspace_root_identity

    def _supports_descriptor_relative_lease_open(self) -> bool:
        return _DESCRIPTOR_RELATIVE_LEASE_OPEN_SUPPORTED

    def _revalidate_run_root(self) -> None:
        if self._run_root_identity is None:
            return
        try:
            if descriptor_relative_authority_supported():
                current = pin_directory_identity(
                    self.run_root,
                    label="run persistence directory",
                )
            else:
                observed = self.run_root.stat(follow_symlinks=False)
                if not stat.S_ISDIR(observed.st_mode):
                    raise OSError("run persistence directory is not a regular directory")
                current = _identity(observed)
        except (OSError, RuntimeError, ValueError) as exc:
            raise OSError("run persistence directory identity could not be revalidated") from exc
        if current != self._run_root_identity:
            raise OSError("run persistence directory changed identity during lease acquisition")

    def _revalidate_workspace_root(self) -> None:
        if self._workspace_root_identity is None:
            return
        try:
            current = pin_directory_identity(self.workspace, label="target workspace")
        except (OSError, RuntimeError, ValueError) as exc:
            raise OSError("target workspace identity could not be revalidated") from exc
        if current != self._workspace_root_identity:
            raise OSError("target workspace changed identity during lease acquisition")

    def _lock_workspace_root(self) -> int | None:
        """Lock the target inode so lease-directory substitution cannot fork authority."""

        if self._workspace_root_identity is None:
            return None
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open(self.workspace, flags)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _identity(opened) != self._workspace_root_identity
            ):
                raise OSError("target workspace changed identity during lease acquisition")
            try:
                import fcntl
            except ImportError as exc:  # pragma: no cover - guarded POSIX capability
                raise OSError("target workspace inode locking is unavailable") from exc
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise WorkspaceBusyError("target workspace is already leased") from exc
            self._revalidate_workspace_root()
            return fd
        except Exception:
            os.close(fd)
            raise

    @staticmethod
    def _unlock_workspace_root(fd: int) -> None:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - guarded POSIX capability
            return
        fcntl.flock(fd, fcntl.LOCK_UN)

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
                    or _identity(opened_directory) != self._lease_root_identity
                    or _identity(current_directory) != self._lease_root_identity
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
        if (
            not stat.S_ISDIR(before_directory.st_mode)
            or _identity(before_directory) != self._lease_root_identity
        ):
            raise OSError("workspace lease directory changed identity during lock open")
        fd = os.open(self.path, flags, 0o600)
        try:
            opened_file = os.fstat(fd)
            current_file = self.path.stat(follow_symlinks=False)
            after_directory = lease_root.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(after_directory.st_mode)
                or _identity(after_directory) != self._lease_root_identity
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
        try:
            current_directory = lease_root.stat(follow_symlinks=False)
        except OSError as exc:
            raise OSError(
                "workspace lease directory changed identity during lease acquisition"
            ) from exc
        if (
            not stat.S_ISDIR(current_directory.st_mode)
            or _identity(current_directory) != self._lease_root_identity
        ):
            raise OSError("workspace lease directory changed identity during lease acquisition")
        if directory_fd is None:
            return
        opened_directory = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or _identity(opened_directory) != self._lease_root_identity
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
        if "workspace_root_identity" in previous:
            root_identity = previous["workspace_root_identity"]
            if root_identity is not None:
                if not isinstance(root_identity, dict) or set(root_identity) != {"device", "inode"}:
                    raise OSError("workspace lease root identity authority is invalid")
                device = root_identity.get("device")
                inode = root_identity.get("inode")
                if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
                    raise OSError("workspace lease root identity authority is invalid")
        if "run_root_identity" in previous:
            run_root_identity = previous["run_root_identity"]
            if run_root_identity is not None:
                if not isinstance(run_root_identity, dict) or set(run_root_identity) != {
                    "device",
                    "inode",
                }:
                    raise OSError("workspace lease run-root identity authority is invalid")
                device = run_root_identity.get("device")
                inode = run_root_identity.get("inode")
                if type(device) is not int or type(inode) is not int or device < 0 or inode < 0:
                    raise OSError("workspace lease run-root identity authority is invalid")
        return previous

    def acquire(self) -> WorkspaceLease:
        self._revalidate_run_root()
        self._revalidate_workspace_root()
        workspace_lock_fd = self._lock_workspace_root()
        try:
            stream, directory_fd = self._open_owned_stream()
        except Exception:
            if workspace_lock_fd is not None:
                with suppress(OSError):
                    self._unlock_workspace_root(workspace_lock_fd)
                os.close(workspace_lock_fd)
            raise
        locked = False
        authority_bound = False
        try:
            self._lock_stream(stream)
            locked = True
            self._revalidate_lease_root(directory_fd)
            self._revalidate_workspace_root()
            stream.seek(0)
            raw = stream.read(_MAX_LEASE_METADATA_BYTES + 1)
            if len(raw) > _MAX_LEASE_METADATA_BYTES:
                raise OSError("workspace lease metadata exceeds bounded ingestion limit")
            self.previous_metadata = self._parse_previous_metadata(raw)
            self._revalidate_run_root()

            workspace_root_identity = (
                {
                    "device": self._workspace_root_identity[0],
                    "inode": self._workspace_root_identity[1],
                }
                if self._workspace_root_identity is not None
                else None
            )
            run_root_identity = (
                {
                    "device": self._run_root_identity[0],
                    "inode": self._run_root_identity[1],
                }
                if self._run_root_identity is not None
                else None
            )
            metadata = {
                "lease_id": self.lease_id,
                "run_id": self.run_id,
                "workspace": str(self.workspace),
                "workspace_root_identity": workspace_root_identity,
                "run_root_identity": run_root_identity,
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
            self._revalidate_run_root()
            self._revalidate_workspace_root()
            bind_active_workspace_authority(
                self.workspace,
                self._workspace_root_identity,
                owner=self.lease_id,
            )
            authority_bound = self._workspace_root_identity is not None
            self._authority_bound = authority_bound
            self._revalidate_run_root()
            self._revalidate_workspace_root()
            self._stream = stream
            self._workspace_lock_fd = workspace_lock_fd
            return self
        except Exception:
            if authority_bound:
                clear_active_workspace_authority(
                    self.workspace,
                    self._workspace_root_identity,
                    owner=self.lease_id,
                )
                self._authority_bound = False
            if locked:
                with suppress(OSError):
                    self._unlock_stream(stream)
            stream.close()
            if workspace_lock_fd is not None:
                with suppress(OSError):
                    self._unlock_workspace_root(workspace_lock_fd)
                os.close(workspace_lock_fd)
            raise
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def release(self) -> None:
        stream = self._stream
        workspace_lock_fd = self._workspace_lock_fd
        self._stream = None
        self._workspace_lock_fd = None
        authority_cleared = True
        if self._authority_bound:
            authority_cleared = clear_active_workspace_authority(
                self.workspace,
                self._workspace_root_identity,
                owner=self.lease_id,
            )
            if authority_cleared:
                self._authority_bound = False
        try:
            if stream is not None:
                try:
                    self._unlock_stream(stream)
                finally:
                    stream.close()
        finally:
            if workspace_lock_fd is not None:
                try:
                    self._unlock_workspace_root(workspace_lock_fd)
                finally:
                    os.close(workspace_lock_fd)
        if not authority_cleared:
            raise OSError("active workspace authority is owned by another lease")

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
