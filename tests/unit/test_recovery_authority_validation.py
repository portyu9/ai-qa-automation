from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState, TerminalStatus
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.state import StateStore


def _prepare_run(tmp_path: Path, runtime_payload: dict[str, object]) -> Path:
    run_dir = tmp_path / "run-1"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state = AgentRunState(
        run_id="run-1",
        objective="Inspect persisted recovery authority",
        workspace=str(workspace),
        terminal_status=TerminalStatus.NOT_VERIFIED,
        terminal_reason="persisted for recovery inspection",
    )
    StateStore(run_dir / "state.json").save(state)
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    (run_dir / "runtime.json").write_text(
        json.dumps(runtime_payload, sort_keys=True),
        encoding="utf-8",
    )
    return run_dir


@pytest.mark.parametrize(
    "pending_mutation",
    [False, 0, "", [], {}],
)
def test_recovery_inspection_rejects_coercive_or_empty_pending_mutation_authority(
    tmp_path: Path,
    pending_mutation: object,
) -> None:
    run_dir = _prepare_run(tmp_path, {"pending_mutation": pending_mutation})

    result = inspect_recovery(run_dir)

    assert result == {
        "recoverable": False,
        "reason": "runtime.json pending_mutation authority is invalid",
    }


def test_recovery_inspection_rejects_missing_pending_mutation_authority(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path, {"workspace": str(tmp_path / "sut")})

    result = inspect_recovery(run_dir)

    assert result == {
        "recoverable": False,
        "reason": "runtime.json is missing pending_mutation authority",
    }
