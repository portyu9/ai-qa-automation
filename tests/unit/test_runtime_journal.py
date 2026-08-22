from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.budget import BudgetExceededError
from ai_qa_automation.runtime.journal import RunJournal


def test_journal_builds_and_verifies_hash_chain(tmp_path: Path) -> None:
    path = tmp_path / "run" / "journal.jsonl"
    journal = RunJournal(path)

    first = journal.append("run_started", run_id="run-1")
    second = journal.append("tool_completed", tool="pytest", status="PASS")

    assert first != second
    assert journal.event_count == 2
    assert journal.head_hash == second
    assert journal.verify() == {"valid": True, "events": 2, "head_hash": second}

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert records[0]["prev_hash"] is None
    assert records[1]["prev_hash"] == records[0]["record_hash"]


def test_journal_detects_tampering_and_refuses_corrupt_reopen(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    journal.append("evidence_registered", evidence_id="ev-1")
    journal.append("validation_completed", status="PASS")

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    records[0]["payload"]["evidence_id"] = "tampered"
    path.write_text("\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n", encoding="utf-8")

    assert journal.verify()["valid"] is False
    with pytest.raises(RuntimeError, match="hash-chain verification"):
        RunJournal(path)


def test_journal_event_budget_is_fail_closed(tmp_path: Path) -> None:
    journal = RunJournal(tmp_path / "journal.jsonl", max_events=1)
    journal.append("first")

    with pytest.raises(BudgetExceededError, match="event budget"):
        journal.append("second")

    assert journal.try_append("third") is False
    assert journal.event_count == 1


def test_regulated_journal_fsync_path_remains_verifiable(tmp_path: Path) -> None:
    journal = RunJournal(tmp_path / "regulated.jsonl", regulated_mode=True)
    journal.append("regulated_event", classification="audit")

    result = journal.verify()
    assert result["valid"] is True
    assert result["events"] == 1
    assert isinstance(result["head_hash"], str)


@pytest.mark.parametrize("max_events", [0, -1, True, 1.5])
def test_journal_rejects_invalid_event_bound(tmp_path: Path, max_events: object) -> None:
    with pytest.raises(ValueError, match="max_events"):
        RunJournal(
            tmp_path / "invalid.jsonl",
            max_events=max_events,  # type: ignore[arg-type]
        )


def test_journal_rejects_oversized_restore_line_before_json_parse(tmp_path: Path) -> None:
    path = tmp_path / "oversized.jsonl"
    path.write_bytes(b"{" + (b"x" * 1_000_001) + b"}\n")

    with pytest.raises(RuntimeError, match="hash-chain verification"):
        RunJournal(path)
