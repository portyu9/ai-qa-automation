from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from _thread import RLock
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from ..fs_authority import descriptor_relative_authority_supported, pin_directory_identity
from ..io_safety import fsync_directory, open_regular_binary, parse_json_object_strict
from ..redaction import sanitize
from ..telemetry import (
    record_mcp_outcome,
    record_policy_denial,
    record_run_metrics,
    record_tool_event,
)
from .budget import BudgetExceededError

_MAX_JOURNAL_LINE_BYTES = 1_000_000
_MAX_JOURNAL_BYTES = 64_000_000
_MAX_RESTORE_EVENTS = 100_000
_LOWER_HEX = frozenset("0123456789abcdef")


def _identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def _stable_file_signature(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def validate_runtime_journal_binding(
    runtime_metadata: dict[str, Any],
    journal_status: dict[str, Any],
) -> dict[str, Any]:
    """Bind a verified journal to the exact head/count persisted by RuntimeControl."""
    if journal_status.get("valid") is not True:
        return {"valid": False, "reason": "journal hash chain is invalid"}
    if "journal_event_count" not in runtime_metadata:
        return {"valid": False, "reason": "runtime journal_event_count authority is missing"}
    expected_events = runtime_metadata["journal_event_count"]
    if type(expected_events) is not int or expected_events < 0:
        return {"valid": False, "reason": "runtime journal_event_count authority is invalid"}
    if "journal_head_hash" not in runtime_metadata:
        return {"valid": False, "reason": "runtime journal_head_hash authority is missing"}
    expected_head = runtime_metadata["journal_head_hash"]
    if expected_head is not None and (
        not isinstance(expected_head, str)
        or len(expected_head) != 64
        or any(character not in _LOWER_HEX for character in expected_head)
    ):
        return {"valid": False, "reason": "runtime journal_head_hash authority is invalid"}
    if expected_events == 0 and expected_head is not None:
        return {"valid": False, "reason": "empty runtime journal must not have a head hash"}
    if expected_events > 0 and expected_head is None:
        return {"valid": False, "reason": "non-empty runtime journal is missing its head hash"}

    actual_events = journal_status.get("events")
    actual_head = journal_status.get("head_hash")
    if type(actual_events) is not int or actual_events < 0:
        return {"valid": False, "reason": "verified journal event count is invalid"}
    if actual_head is not None and not isinstance(actual_head, str):
        return {"valid": False, "reason": "verified journal head hash is invalid"}
    if actual_events != expected_events or actual_head != expected_head:
        return {
            "valid": False,
            "reason": "runtime journal authority does not match persisted journal",
            "expected_events": expected_events,
            "actual_events": actual_events,
            "expected_head_hash": expected_head,
            "actual_head_hash": actual_head,
        }
    return {
        "valid": True,
        "events": expected_events,
        "head_hash": expected_head,
    }


def _record_event_metrics(event: str, payload: dict[str, Any]) -> None:
    """Project durable lifecycle truth into optional, low-cardinality telemetry."""
    try:
        tool_name = str(payload.get("tool_name") or "")
        if event == "agent_run_finished":
            record_run_metrics(
                terminal_status=payload.get("terminal_status"),
                duration_seconds=payload.get("duration_seconds"),
                tool_calls=payload.get("tool_calls"),
            )
        elif event == "tool_requested" and tool_name:
            record_tool_event(tool_name, "requested")
        elif event == "tool_completed" and tool_name:
            failed = bool(payload.get("failed"))
            record_tool_event(tool_name, "failed" if failed else "succeeded")
            if tool_name.startswith(("mcp__github__", "mcp__atlassian__")):
                provider = tool_name.split("__", 2)[1]
                record_mcp_outcome(provider, "FAILED" if failed else "AVAILABLE")
        elif event == "tool_failed" and tool_name:
            record_tool_event(tool_name, "failed")
            if tool_name.startswith(("mcp__github__", "mcp__atlassian__")):
                provider = tool_name.split("__", 2)[1]
                record_mcp_outcome(provider, "FAILED")
        elif event == "policy_denied":
            if tool_name:
                record_tool_event(tool_name, "denied")
            record_policy_denial("deterministic_policy")
        elif event == "circuit_denied":
            if tool_name:
                record_tool_event(tool_name, "denied")
            record_policy_denial("runtime_circuit")
        elif event == "budget_denied":
            if tool_name:
                record_tool_event(tool_name, "denied")
            record_policy_denial("runtime_budget")
        elif event in {
            "workspace_drift_blocked",
            "workspace_fingerprint_incomplete",
            "mutation_blocked_non_git_workspace",
            "post_mutation_fingerprint_incomplete",
        }:
            record_policy_denial("workspace_integrity")
        elif event == "mutation_prepare_denied":
            if tool_name:
                record_tool_event(tool_name, "denied")
            record_policy_denial("mutation_transaction")
    except Exception:
        # Metrics are observational only. They may never break journal durability,
        # authorization, evidence persistence, mutation closure, or terminal truth.
        return


class RunJournal:
    """Append-only hash-chained JSONL lifecycle journal."""

    def __init__(
        self,
        path: Path,
        *,
        regulated_mode: bool = False,
        max_events: int = 5000,
        expected_parent_identity: tuple[int, int] | None = None,
    ) -> None:
        if isinstance(max_events, bool) or not isinstance(max_events, int) or max_events < 1:
            raise ValueError("max_events must be a positive integer")
        requested = path.expanduser()
        if requested.is_symlink():
            raise ValueError("run journal path is a symlink and has ambiguous ownership")
        raw_parent = requested.parent
        if raw_parent.is_symlink():
            raise ValueError("run journal directory is a symlink and has ambiguous ownership")
        raw_parent.mkdir(parents=True, exist_ok=True)
        if raw_parent.is_symlink():
            raise ValueError("run journal directory became a symlink")
        self.path = raw_parent.resolve() / requested.name
        parent_status = self.path.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_status.st_mode):
            raise ValueError("run journal directory must remain a regular directory")
        self._descriptor_relative_parent = descriptor_relative_authority_supported()
        self._parent_identity = (
            pin_directory_identity(self.path.parent, label="run journal directory")
            if self._descriptor_relative_parent
            else _identity(parent_status)
        )
        if (
            expected_parent_identity is not None
            and self._parent_identity != expected_parent_identity
        ):
            raise ValueError("run journal directory does not match authorized run persistence root")
        self.regulated_mode = regulated_mode
        self.max_events = max_events
        self._lock = RLock()
        self._seq, self._head = self._inspect_existing()

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._seq

    @property
    def head_hash(self) -> str | None:
        with self._lock:
            return self._head

    def _revalidate_parent(self, parent_fd: int | None = None) -> None:
        try:
            current = self.path.parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeError(
                "run journal directory changed identity and ownership is ambiguous"
            ) from exc
        if not stat.S_ISDIR(current.st_mode) or _identity(current) != self._parent_identity:
            raise RuntimeError("run journal directory changed identity and ownership is ambiguous")
        if parent_fd is None:
            return
        opened = os.fstat(parent_fd)
        if not stat.S_ISDIR(opened.st_mode) or _identity(opened) != self._parent_identity:
            raise RuntimeError("run journal directory changed identity and ownership is ambiguous")

    @contextmanager
    def _pinned_parent(self) -> Iterator[int | None]:
        if not self._descriptor_relative_parent:
            self._revalidate_parent()
            try:
                yield None
            except BaseException:
                raise
            else:
                self._revalidate_parent()
            return

        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            parent_fd = os.open(self.path.parent, flags)
        except OSError as exc:
            raise RuntimeError(
                "run journal directory changed identity and ownership is ambiguous"
            ) from exc
        try:
            self._revalidate_parent(parent_fd)
            try:
                yield parent_fd
            except BaseException:
                raise
            else:
                self._revalidate_parent(parent_fd)
        finally:
            os.close(parent_fd)

    def _stat_entry(self, parent_fd: int | None) -> os.stat_result:
        if parent_fd is None:
            return self.path.stat(follow_symlinks=False)
        return os.stat(self.path.name, dir_fd=parent_fd, follow_symlinks=False)

    def _entry_exists(self, parent_fd: int | None) -> bool:
        try:
            self._stat_entry(parent_fd)
        except FileNotFoundError:
            return False
        return True

    def _assert_owned_path(self, parent_fd: int | None = None) -> None:
        self._revalidate_parent(parent_fd)
        try:
            current = self._stat_entry(parent_fd)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(current.st_mode):
            raise RuntimeError("run journal path became a symlink and ownership is ambiguous")

    def _open_entry(self, parent_fd: int | None, flags: int, mode: int = 0o600) -> int:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if nofollow:
            flags |= nofollow
        try:
            if parent_fd is None:
                return os.open(self.path, flags, mode)
            return os.open(self.path.name, flags, mode, dir_fd=parent_fd)
        except OSError as exc:
            if nofollow and exc.errno == errno.ELOOP:
                raise RuntimeError(
                    "run journal became a symlink during open and ownership is ambiguous"
                ) from exc
            raise

    def _assert_opened_entry_current(
        self,
        *,
        parent_fd: int | None,
        opened: os.stat_result,
        label: str,
    ) -> os.stat_result:
        try:
            current = self._stat_entry(parent_fd)
        except OSError as exc:
            raise RuntimeError(f"run journal changed identity during {label}") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or _identity(opened) != _identity(current)
        ):
            raise RuntimeError(f"run journal changed identity during {label}")
        return current

    def append(self, event: str, **payload: Any) -> str:
        safe_payload = sanitize(payload)
        with self._lock:
            if self._seq >= self.max_events:
                raise BudgetExceededError("run-journal event budget exhausted")
            body = {
                "seq": self._seq + 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                "payload": safe_payload,
                "prev_hash": self._head,
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
            record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            rendered = (
                json.dumps({**body, "record_hash": record_hash}, sort_keys=True, default=str) + "\n"
            )
            rendered_bytes = rendered.encode("utf-8")
            if len(rendered_bytes) > _MAX_JOURNAL_LINE_BYTES:
                raise ValueError("run-journal event exceeds line-size bound")

            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
            with self._pinned_parent() as parent_fd:
                self._assert_owned_path(parent_fd)
                fd = self._open_entry(parent_fd, flags)
                try:
                    initial = os.fstat(fd)
                    self._assert_opened_entry_current(
                        parent_fd=parent_fd,
                        opened=initial,
                        label="append open",
                    )
                    self._revalidate_parent(parent_fd)
                    if initial.st_size + len(rendered_bytes) > _MAX_JOURNAL_BYTES:
                        raise BudgetExceededError("run-journal byte budget exhausted")
                    with os.fdopen(fd, "a", encoding="utf-8") as stream:
                        fd = -1
                        stream.write(rendered)
                        stream.flush()
                        # Journal lineage is authority-bearing in every runtime mode.
                        # Regulated mode may add policy, but durability is not optional.
                        os.fsync(stream.fileno())
                    final_current = self._stat_entry(parent_fd)
                    if not stat.S_ISREG(final_current.st_mode) or _identity(
                        final_current
                    ) != _identity(initial):
                        raise RuntimeError("run journal changed identity during append")
                    if initial.st_size == 0:
                        if parent_fd is not None:
                            os.fsync(parent_fd)
                        else:
                            fsync_directory(self.path.parent)
                finally:
                    if fd >= 0:
                        os.close(fd)
            self._seq += 1
            self._head = record_hash
        if isinstance(safe_payload, dict):
            _record_event_metrics(event, safe_payload)
        return record_hash

    def try_append(self, event: str, **payload: Any) -> bool:
        try:
            self.append(event, **payload)
        except BudgetExceededError:
            return False
        return True

    def _verify_stream(self, stream: BinaryIO) -> dict[str, Any]:
        previous: str | None = None
        count = 0
        total_bytes = 0
        expected_seq = 1
        restore_limit = max(self.max_events, _MAX_RESTORE_EVENTS)
        while True:
            raw = stream.readline(_MAX_JOURNAL_LINE_BYTES + 1)
            if not raw:
                break
            total_bytes += len(raw)
            if total_bytes > _MAX_JOURNAL_BYTES:
                return {"valid": False, "events": count, "head_hash": previous}
            if len(raw) > _MAX_JOURNAL_LINE_BYTES:
                return {"valid": False, "events": count, "head_hash": previous}
            if not raw.strip():
                continue
            if count >= restore_limit:
                return {"valid": False, "events": count, "head_hash": previous}
            try:
                record = parse_json_object_strict(
                    raw.decode("utf-8"),
                    label=f"run journal record {expected_seq}",
                )
                sequence = record.get("seq")
                if type(sequence) is not int or sequence != expected_seq:
                    return {"valid": False, "events": count, "head_hash": previous}
                body = {key: value for key, value in record.items() if key != "record_hash"}
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
            except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
                return {"valid": False, "events": count, "head_hash": previous}
            actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if record.get("prev_hash") != previous or record.get("record_hash") != actual:
                return {"valid": False, "events": count, "head_hash": previous}
            previous = actual
            count += 1
            expected_seq += 1
        return {"valid": True, "events": count, "head_hash": previous}

    def verify(self) -> dict[str, Any]:
        with self._lock, self._pinned_parent() as parent_fd:
            self._assert_owned_path(parent_fd)
            if not self._entry_exists(parent_fd):
                return {"valid": True, "events": 0, "head_hash": None}

            if parent_fd is None:
                with open_regular_binary(self.path, label="run journal") as stream:
                    return self._verify_stream(stream)

            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            fd = self._open_entry(parent_fd, flags)
            try:
                initial = os.fstat(fd)
                self._assert_opened_entry_current(
                    parent_fd=parent_fd,
                    opened=initial,
                    label="verification open",
                )
                self._revalidate_parent(parent_fd)
                initial_signature = _stable_file_signature(initial)
                stream = os.fdopen(fd, "rb", closefd=False)
                try:
                    result = self._verify_stream(stream)
                finally:
                    stream.close()
                final_opened = os.fstat(fd)
                final_current = self._assert_opened_entry_current(
                    parent_fd=parent_fd,
                    opened=final_opened,
                    label="verification",
                )
                if (
                    _stable_file_signature(final_opened) != initial_signature
                    or _stable_file_signature(final_current) != initial_signature
                ):
                    raise RuntimeError("run journal changed during verification")
                return result
            finally:
                os.close(fd)

    def _inspect_existing(self) -> tuple[int, str | None]:
        result = self.verify()
        if not result["valid"]:
            raise RuntimeError("existing run journal failed hash-chain verification")
        return int(result["events"]), result["head_hash"]
