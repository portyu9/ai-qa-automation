from __future__ import annotations

import hashlib
import json
import os
from _thread import RLock
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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

    def __init__(self, path: Path, *, regulated_mode: bool = False, max_events: int = 5000) -> None:
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

    def _assert_owned_path(self) -> None:
        if self.path.parent.is_symlink():
            raise RuntimeError("run journal directory became a symlink and ownership is ambiguous")
        if self.path.is_symlink():
            raise RuntimeError("run journal path became a symlink and ownership is ambiguous")

    def append(self, event: str, **payload: Any) -> str:
        safe_payload = sanitize(payload)
        with self._lock:
            self._assert_owned_path()
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
            existing_size = self.path.stat().st_size if self.path.exists() else 0
            if existing_size + len(rendered_bytes) > _MAX_JOURNAL_BYTES:
                raise BudgetExceededError("run-journal byte budget exhausted")
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                if self.regulated_mode:
                    os.fsync(stream.fileno())
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

    def verify(self) -> dict[str, Any]:
        with self._lock:
            self._assert_owned_path()
            previous: str | None = None
            count = 0
            total_bytes = 0
            expected_seq = 1
            if not self.path.exists():
                return {"valid": True, "events": 0, "head_hash": None}
            # Read byte-bounded lines so a corrupted or adversarial JSONL record cannot
            # turn recovery/attestation into an unbounded-memory or unbounded-I/O operation.
            restore_limit = max(self.max_events, _MAX_RESTORE_EVENTS)
            with self.path.open("rb") as stream:
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
                        record = json.loads(raw.decode("utf-8"))
                        if not isinstance(record, dict):
                            return {"valid": False, "events": count, "head_hash": previous}
                        if record.get("seq") != expected_seq:
                            return {"valid": False, "events": count, "head_hash": previous}
                        body = {key: value for key, value in record.items() if key != "record_hash"}
                        canonical = json.dumps(
                            body, sort_keys=True, separators=(",", ":"), default=str
                        )
                    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
                        return {"valid": False, "events": count, "head_hash": previous}
                    actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    if record.get("prev_hash") != previous or record.get("record_hash") != actual:
                        return {"valid": False, "events": count, "head_hash": previous}
                    previous = actual
                    count += 1
                    expected_seq += 1
            return {"valid": True, "events": count, "head_hash": previous}

    def _inspect_existing(self) -> tuple[int, str | None]:
        result = self.verify()
        if not result["valid"]:
            raise RuntimeError("existing run journal failed hash-chain verification")
        return int(result["events"]), result["head_hash"]
