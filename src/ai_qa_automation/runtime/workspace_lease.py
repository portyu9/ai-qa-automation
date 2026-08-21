from __future__ import annotations

import hashlib
import json
import os
import socket
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


class WorkspaceBusyError(RuntimeError):
    """Raised when another agent process already holds the target-workspace lease."""


class WorkspaceLease(AbstractContextManager["WorkspaceLease"]):
    """Cross-process workspace lease stored outside the untrusted target repository."""

    def __init__(self, artifact_root: Path, workspace: Path, run_id: str) -> None:
        self.artifact_root = artifact_root.expanduser().resolve()
        self.workspace = workspace.expanduser().resolve()
        self.run_id = run_id
        key = hashlib.sha256(str(self.workspace).encode("utf-8")).hexdigest()[:24]
        self.path = self.artifact_root / ".leases" / f"{key}.lock"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_id = f"lease-{uuid4().hex[:16]}"
        self._stream: Any | None = None
        self.previous_metadata: dict[str, Any] | None = None

    def acquire(self) -> "WorkspaceLease":
        stream = self.path.open("a+", encoding="utf-8")
        try:
            self._lock_stream(stream)
        except Exception:
            stream.close()
            raise
        stream.seek(0)
        raw = stream.read().strip().strip("\0")
        if raw:
            try:
                previous = json.loads(raw)
            except json.JSONDecodeError:
                previous = None
            self.previous_metadata = previous if isinstance(previous, dict) else None
        else:
            self.previous_metadata = None
        metadata = {
            "lease_id": self.lease_id,
            "run_id": self.run_id,
            "workspace": str(self.workspace),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "acquired_at": datetime.now(UTC).isoformat(),
        }
        stream.seek(0)
        stream.truncate(0)
        stream.write(json.dumps(metadata, sort_keys=True))
        stream.flush()
        os.fsync(stream.fileno())
        self._stream = stream
        return self

    def release(self) -> None:
        if self._stream is None:
            return
        try:
            self._unlock_stream(self._stream)
        finally:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> "WorkspaceLease":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()

    @staticmethod
    def _lock_stream(stream: Any) -> None:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows path
            import msvcrt

            try:
                stream.seek(0, os.SEEK_END)
                if stream.tell() == 0:
                    stream.write("\0")
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
            import msvcrt

            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
