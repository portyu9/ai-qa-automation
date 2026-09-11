from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
import stat
from _thread import RLock
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from ..fs_authority import descriptor_relative_authority_supported, pin_directory_identity
from ..io_safety import fsync_directory, parse_json_object_strict
from ..tools.subprocess_subject import (
    bind_active_workspace_authority,
    clear_active_workspace_authority,
    owns_active_workspace_authority,
)


class _MSVCRTLocking(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, fd: int, mode: int, nbytes: int) -> None: ...


class MutationRecoveryClosureGuard(Protocol):
    """Bind one runtime's frozen mutation authority to lease teardown."""

    def __call__(
        self,
        *,
        lease_id: str,
        workspace: Path,
        run_root_identity: tuple[int, int] | None,
        workspace_root_identity: tuple[int, int] | None,
    ) -> AbstractContextManager[bool]: ...


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
        self._lifecycle_lock = RLock()
        self._stream: Any | None = None
        self._workspace_lock_fd: int | None = None
        self._authority_bound = False
        self._owner_published = False
        self._mutation_recovery_closed = False
        self._acquired_at: str | None = None
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
        except BaseException:
            with suppress(OSError):
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
                except BaseException:
                    with suppress(OSError):
                        os.close(fd)
                    raise
            except BaseException:
                with suppress(OSError):
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
        except BaseException:
            with suppress(OSError):
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
        if (
            "mutation_recovery_closed" in previous
            and type(previous["mutation_recovery_closed"]) is not bool
        ):
            raise OSError("workspace lease mutation recovery closure authority is invalid")
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

    def _current_metadata_bytes(self) -> bytes:
        acquired_at = self._acquired_at
        if acquired_at is None:
            raise OSError("workspace lease acquisition time is unavailable")
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
            "mutation_recovery_closed": self._mutation_recovery_closed,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "acquired_at": acquired_at,
        }
        rendered = json.dumps(metadata, sort_keys=True).encode("utf-8")
        if len(rendered) > _MAX_LEASE_METADATA_BYTES:
            raise OSError("workspace lease metadata exceeds persistence limit")
        return rendered

    def _persist_current_owner(self, stream: Any, directory_fd: int | None) -> None:
        rendered = self._current_metadata_bytes()
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

    def acquire(self, *, publish: bool = True) -> WorkspaceLease:
        with self._lifecycle_lock:
            if self._stream is not None:
                raise OSError("workspace lease is already acquired")
            return self._acquire_locked(publish=publish)

    def _acquire_locked(self, *, publish: bool) -> WorkspaceLease:
        self._revalidate_run_root()
        self._revalidate_workspace_root()
        workspace_lock_fd = self._lock_workspace_root()
        try:
            stream, directory_fd = self._open_owned_stream()
        except BaseException:
            if workspace_lock_fd is not None:
                try:
                    with suppress(OSError):
                        self._unlock_workspace_root(workspace_lock_fd)
                finally:
                    with suppress(OSError):
                        os.close(workspace_lock_fd)
            raise
        locked = False
        authority_cleanup_required = False
        try:
            self._lock_stream(stream)
            locked = True
            self._revalidate_lease_root(directory_fd)
            self._revalidate_workspace_root()
            self._acquired_at = datetime.now(UTC).isoformat()
            self._mutation_recovery_closed = False
            stream.seek(0)
            raw = stream.read(_MAX_LEASE_METADATA_BYTES + 1)
            if len(raw) > _MAX_LEASE_METADATA_BYTES:
                raise OSError("workspace lease metadata exceeds bounded ingestion limit")
            self.previous_metadata = self._parse_previous_metadata(raw)
            self._revalidate_run_root()

            authority_cleanup_required = self._workspace_root_identity is not None
            try:
                bind_active_workspace_authority(
                    self.workspace,
                    self._workspace_root_identity,
                    owner=self.lease_id,
                )
            except RuntimeError as exc:
                raise OSError(
                    "process-local workspace lease authority conflicts with another live run"
                ) from exc
            self._authority_bound = authority_cleanup_required
            if publish:
                self._persist_current_owner(stream, directory_fd)
            self._revalidate_run_root()
            self._revalidate_workspace_root()
            self._stream = stream
            self._workspace_lock_fd = workspace_lock_fd
            self._owner_published = publish
            return self
        except BaseException as acquisition_error:
            authority_cleared = True
            if authority_cleanup_required:
                try:
                    authority_cleared = clear_active_workspace_authority(
                        self.workspace,
                        self._workspace_root_identity,
                        owner=self.lease_id,
                    )
                except BaseException:
                    authority_cleared = False
                    # Exact owner/identity cleanup is idempotent and replay-safe. One
                    # retry prevents an interruption from stranding process authority.
                    try:
                        authority_cleared = clear_active_workspace_authority(
                            self.workspace,
                            self._workspace_root_identity,
                            owner=self.lease_id,
                        )
                    except BaseException:
                        authority_cleared = False
                if authority_cleared:
                    self._authority_bound = False
                else:
                    acquisition_error.add_note(
                        "Process-local workspace authority cleanup could not be guaranteed."
                    )
            try:
                if locked:
                    with suppress(OSError):
                        self._unlock_stream(stream)
            finally:
                with suppress(OSError):
                    stream.close()
                if workspace_lock_fd is not None:
                    try:
                        with suppress(OSError):
                            self._unlock_workspace_root(workspace_lock_fd)
                    finally:
                        with suppress(OSError):
                            os.close(workspace_lock_fd)
            self._acquired_at = None
            self._mutation_recovery_closed = False
            raise
        finally:
            if directory_fd is not None:
                with suppress(OSError):
                    os.close(directory_fd)

    @contextmanager
    def stale_recovery_authority(
        self,
        *,
        artifact_root: Path,
        workspace: Path,
        recovering_run_id: str,
        previous_lease: dict[str, Any],
    ) -> Iterator[None]:
        """Hold exact live deferred-successor authority across stale recovery."""

        with self._lifecycle_lock:
            stream = self._stream
            if stream is None or self._acquired_at is None:
                raise OSError("stale recovery successor lease is not acquired")
            if self._owner_published:
                raise OSError("stale recovery successor lease was already published")
            if self.run_id != recovering_run_id:
                raise OSError("stale recovery successor lease is bound to a different run")
            if self.artifact_root != artifact_root.expanduser().resolve():
                raise OSError(
                    "stale recovery successor lease is bound to a different artifact root"
                )
            if self.workspace != workspace.expanduser().resolve():
                raise OSError("stale recovery successor lease is bound to a different workspace")

            self._revalidate_lease_root(None)
            self._revalidate_run_root()
            self._revalidate_workspace_root()
            try:
                opened_lease = os.fstat(stream.fileno())
                current_lease = self.path.stat(follow_symlinks=False)
            except OSError as exc:
                raise OSError(
                    "stale recovery successor lease file could not be revalidated"
                ) from exc
            if (
                not stat.S_ISREG(opened_lease.st_mode)
                or not stat.S_ISREG(current_lease.st_mode)
                or _identity(opened_lease) != _identity(current_lease)
            ):
                raise OSError("stale recovery successor lease file changed identity")

            stream.seek(0)
            raw = stream.read(_MAX_LEASE_METADATA_BYTES + 1)
            if len(raw) > _MAX_LEASE_METADATA_BYTES:
                raise OSError("stale recovery predecessor lease metadata exceeds ingestion limit")
            observed_previous = self._parse_previous_metadata(raw)
            if observed_previous != self.previous_metadata or observed_previous != previous_lease:
                raise OSError("stale recovery predecessor handoff does not match successor lease")

            if self._workspace_root_identity is not None:
                workspace_lock_fd = self._workspace_lock_fd
                if workspace_lock_fd is None:
                    raise OSError("stale recovery successor workspace lock is unavailable")
                try:
                    opened_workspace = os.fstat(workspace_lock_fd)
                except OSError as exc:
                    raise OSError(
                        "stale recovery successor workspace lock could not be revalidated"
                    ) from exc
                if (
                    not stat.S_ISDIR(opened_workspace.st_mode)
                    or _identity(opened_workspace) != self._workspace_root_identity
                ):
                    raise OSError("stale recovery successor workspace lock changed identity")
                if not self._authority_bound or not owns_active_workspace_authority(
                    self.workspace,
                    self._workspace_root_identity,
                    owner=self.lease_id,
                ):
                    raise OSError(
                        "stale recovery successor process-local workspace authority is not live"
                    )
            yield

    def publish_current_owner(self) -> WorkspaceLease:
        """Durably replace predecessor metadata only after stale recovery is resolved."""

        with self._lifecycle_lock:
            stream = self._stream
            if stream is None:
                raise OSError("workspace lease must be acquired before owner publication")
            if self._owner_published:
                return self
            self._revalidate_run_root()
            self._revalidate_workspace_root()
            self._mutation_recovery_closed = False
            self._persist_current_owner(stream, None)
            self._owner_published = True
            return self

    def release(
        self,
        *,
        recovery_closure_guard: MutationRecoveryClosureGuard | None = None,
    ) -> None:
        with self._lifecycle_lock:
            self._release_locked(recovery_closure_guard=recovery_closure_guard)

    def _release_locked(
        self,
        *,
        recovery_closure_guard: MutationRecoveryClosureGuard | None,
    ) -> None:
        stream = self._stream
        workspace_lock_fd = self._workspace_lock_fd
        closure_error: BaseException | None = None
        if stream is not None and self._owner_published and recovery_closure_guard is not None:
            try:
                with recovery_closure_guard(
                    lease_id=self.lease_id,
                    workspace=self.workspace,
                    run_root_identity=self._run_root_identity,
                    workspace_root_identity=self._workspace_root_identity,
                ) as recovery_closed:
                    if type(recovery_closed) is not bool:
                        raise OSError("mutation recovery closure guard returned invalid authority")
                    if recovery_closed:
                        self._mutation_recovery_closed = True
                        self._persist_current_owner(stream, None)
            except BaseException as exc:
                closure_error = exc

        authority_cleared = True
        authority_error: BaseException | None = None
        try:
            if self._authority_bound:
                try:
                    authority_cleared = clear_active_workspace_authority(
                        self.workspace,
                        self._workspace_root_identity,
                        owner=self.lease_id,
                    )
                except BaseException as exc:
                    authority_error = exc
                    authority_cleared = False
                    # Exact process-local release is idempotent and replay-safe. Retry only
                    # this same owner/identity once so interruption cannot strand authority.
                    try:
                        authority_cleared = clear_active_workspace_authority(
                            self.workspace,
                            self._workspace_root_identity,
                            owner=self.lease_id,
                        )
                    except BaseException:
                        authority_cleared = False
                if authority_cleared:
                    self._authority_bound = False
        finally:
            try:
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
            finally:
                self._stream = None
                self._workspace_lock_fd = None
                self._owner_published = False
                self._acquired_at = None
                self._mutation_recovery_closed = False

        if authority_error is not None:
            if closure_error is not None:
                authority_error.add_note(
                    "Workspace lease mutation recovery closure also could not be persisted safely."
                )
            if isinstance(authority_error, Exception):
                raise OSError(
                    "active workspace authority release was interrupted or failed"
                ) from authority_error
            raise authority_error
        if not authority_cleared:
            error = OSError("active workspace authority is owned by another lease")
            if closure_error is not None:
                error.add_note(
                    "Workspace lease mutation recovery closure also could not be persisted safely."
                )
            raise error
        if closure_error is not None:
            if isinstance(closure_error, Exception):
                raise OSError(
                    "workspace lease mutation recovery closure could not be persisted safely"
                ) from closure_error
            raise closure_error

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
