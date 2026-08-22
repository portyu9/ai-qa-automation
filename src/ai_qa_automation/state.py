from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import AgentRunState

_MAX_STATE_BYTES = 16_000_000


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(self, path: Path) -> None:
        requested = path.expanduser()
        if requested.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")
        raw_parent = requested.parent
        if raw_parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")
        raw_parent.mkdir(parents=True, exist_ok=True)
        if raw_parent.is_symlink():
            raise ValueError("state directory became a symlink")
        self.path = raw_parent.resolve() / requested.name
        self._assert_owned()

    def _assert_owned(self) -> None:
        if self.path.parent.is_symlink():
            raise ValueError("state directory is a symlink and has ambiguous ownership")
        if self.path.is_symlink():
            raise ValueError("state path is a symlink and has ambiguous ownership")

    def save(self, state: AgentRunState) -> None:
        self._assert_owned()
        rendered = state.model_dump_json(indent=2)
        if len(rendered.encode("utf-8")) > _MAX_STATE_BYTES:
            raise ValueError("canonical state exceeds persistence size bound")
        handle, raw_temp = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            text=True,
        )
        temp = Path(raw_temp)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            self._assert_owned()
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)

    def load(self) -> AgentRunState:
        self._assert_owned()
        if self.path.stat().st_size > _MAX_STATE_BYTES:
            raise ValueError("canonical state exceeds restore size bound")
        return AgentRunState.model_validate(json.loads(self.path.read_text(encoding="utf-8")))
