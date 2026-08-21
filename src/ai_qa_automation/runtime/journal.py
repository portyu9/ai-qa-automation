from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..redaction import sanitize
from .budget import BudgetExceededError


class RunJournal:
    """Append-only hash-chained JSONL lifecycle journal."""

    def __init__(self, path: Path, *, regulated_mode: bool = False, max_events: int = 5000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be at least 1")
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.regulated_mode = regulated_mode
        self.max_events = max_events
        self._lock = threading.Lock()
        self._seq, self._head = self._inspect_existing()

    @property
    def event_count(self) -> int:
        return self._seq

    @property
    def head_hash(self) -> str | None:
        return self._head

    def append(self, event: str, **payload: Any) -> str:
        with self._lock:
            if self._seq >= self.max_events:
                raise BudgetExceededError("run-journal event budget exhausted")
            body = {
                "seq": self._seq + 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "event": event,
                "payload": sanitize(payload),
                "prev_hash": self._head,
            }
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
            record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({**body, "record_hash": record_hash}, sort_keys=True, default=str) + "\n")
                stream.flush()
                if self.regulated_mode:
                    os.fsync(stream.fileno())
            self._seq += 1
            self._head = record_hash
            return record_hash

    def try_append(self, event: str, **payload: Any) -> bool:
        try:
            self.append(event, **payload)
        except BudgetExceededError:
            return False
        return True

    def verify(self) -> dict[str, Any]:
        previous: str | None = None
        count = 0
        expected_seq = 1
        if not self.path.exists():
            return {"valid": True, "events": 0, "head_hash": None}
        # Journal creation is bounded by max_events; recovery additionally rejects
        # pathological line counts to avoid turning a corrupted artifact into a memory DoS.
        with self.path.open("r", encoding="utf-8") as stream:
            for raw in stream:
                if not raw.strip():
                    continue
                if count >= max(self.max_events, 100_000):
                    return {"valid": False, "events": count, "head_hash": previous}
                record = json.loads(raw)
                if record.get("seq") != expected_seq:
                    return {"valid": False, "events": count, "head_hash": previous}
                body = {key: value for key, value in record.items() if key != "record_hash"}
                canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
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
