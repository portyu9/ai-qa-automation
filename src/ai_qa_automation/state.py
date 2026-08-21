from __future__ import annotations

import json
from pathlib import Path

from .models import AgentRunState


class StateStore:
    """Canonical run state persisted independently from conversational context."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, state: AgentRunState) -> None:
        temp = self.path.with_suffix(".tmp")
        temp.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        temp.replace(self.path)

    def load(self) -> AgentRunState:
        return AgentRunState.model_validate(json.loads(self.path.read_text(encoding="utf-8")))
