from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.run_control import RuntimeControl
from ai_qa_automation.state import StateStore


def _recovery_run(tmp_path: Path, runtime_bytes: bytes) -> Path:
    run_dir = tmp_path / "artifacts" / "run-recovery"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    StateStore(run_dir / "state.json").save(
        AgentRunState(
            run_id="run-recovery",
            objective="recover persisted truth",
            workspace=str(workspace),
        )
    )
    RunJournal(run_dir / "journal.jsonl").append("run_started")
    (run_dir / "runtime.json").write_bytes(runtime_bytes)
    return run_dir


def _runtime_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-control"
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=5,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-control",
    )


def test_recovery_reports_malformed_runtime_json_distinctly(tmp_path: Path) -> None:
    run_dir = _recovery_run(tmp_path, b"{not-json")

    assert inspect_recovery(run_dir) == {
        "recoverable": False,
        "reason": "runtime.json is invalid JSON",
    }


def test_recovery_reports_invalid_runtime_utf8_distinctly(tmp_path: Path) -> None:
    run_dir = _recovery_run(tmp_path, b"\xff\xfe")

    assert inspect_recovery(run_dir) == {
        "recoverable": False,
        "reason": "runtime.json is not valid UTF-8",
    }


def test_new_file_rollback_flushes_existing_parent_after_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _runtime_control(tmp_path)
    relative = "tests/test_generated.py"
    control.prepare_mutation(relative)
    target = control.workspace / relative
    target.parent.mkdir(parents=True)
    target.write_text("def test_generated():\n    assert True\n", encoding="utf-8")

    flushed: list[Path] = []
    real_fsync_directory = run_control_module.fsync_directory

    def record_fsync(path: Path) -> None:
        flushed.append(path)
        real_fsync_directory(path)

    monkeypatch.setattr(run_control_module, "fsync_directory", record_fsync)
    rolled_back = control.rollback_pending_mutation(reason="validation failed")

    assert rolled_back == relative
    assert not target.exists()
    assert target.parent in flushed
    assert control.pending_mutation is None
