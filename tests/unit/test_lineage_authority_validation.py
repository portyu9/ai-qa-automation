from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.lineage import build_run_lineage


def test_lineage_rejects_coercive_canonical_state_revision(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state = AgentRunState(
        run_id="run-1",
        objective="Build strict lineage",
        workspace=str(tmp_path / "sut"),
    )
    payload = state.model_dump(mode="json")
    payload["change_revision"] = "0"
    (run_dir / "state.json").write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="change_revision"):
        build_run_lineage(run_dir)
