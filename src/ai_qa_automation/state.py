from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import AgentRunState


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, state: AgentRunState) -> None:
        handle, raw_temp = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            text=True,
        )
        temp = Path(raw_temp)
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(state.model_dump_json(indent=2))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            temp.unlink(missing_ok=True)

    def load(self) -> AgentRunState:
        return AgentRunState.model_validate(json.loads(self.path.read_text(encoding="utf-8")))
