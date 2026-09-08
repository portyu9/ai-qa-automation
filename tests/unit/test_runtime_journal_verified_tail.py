from __future__ import annotations

from pathlib import Path

from ai_qa_automation.runtime.journal import RunJournal


def test_verified_journal_tail_is_opt_in_and_hash_chain_bound(tmp_path: Path) -> None:
    journal = RunJournal(tmp_path / "journal.jsonl")
    first = journal.append("first", value=1)
    second = journal.append("second", value=2)

    assert journal.verify() == {"valid": True, "events": 2, "head_hash": second}

    inspected = journal.verify(include_last_record=True)
    assert inspected["valid"] is True
    assert inspected["events"] == 2
    assert inspected["head_hash"] == second
    tail = inspected["last_record"]
    assert isinstance(tail, dict)
    assert tail["seq"] == 2
    assert tail["event"] == "second"
    assert tail["payload"] == {"value": 2}
    assert tail["prev_hash"] == first
    assert tail["record_hash"] == second
