from __future__ import annotations

import hashlib
import importlib
import json
import os
import socket
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

    def _open_owned_stream(self) -> Any:
        lease_root = self.path.parent
        if lease_root.is_symlink() or self.path.is_symlink():
            raise OSError("workspace lease path has ambiguous symlink ownership")
        flags = os.O_RDWR | os.O_CREAT
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        fd = os.open(self.path, flags, 0o600)
        return os.fdopen(fd, "r+b")

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
        previous_workspace = str(previous.get("workspace") or "")
        previous_run_id = str(previous.get("run_id") or "")
        previous_lease_id = str(previous.get("lease_id") or "")
        if previous_workspace != str(self.workspace):
            raise OSError("workspace lease metadata is bound to a different workspace")
        if not previous_run_id or not previous_lease_id:
            raise OSError("workspace lease metadata is incomplete; manual review is required")
        return previous

    def acquire(self) -> WorkspaceLease:
        file_existed = self.path.exists()
        stream = self._open_owned_stream()
        locked = False
        try:
            self._lock_stream(stream)
            locked = True
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
            if not file_existed:
                fsync_directory(self.path.parent)
            self._stream = stream
            return self
        except Exception:
            if locked:
                with suppress(OSError):
                    self._unlock_stream(stream)
            stream.close()
            raise

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
