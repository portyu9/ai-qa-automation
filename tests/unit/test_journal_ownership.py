from pathlib import Path

import pytest

from ai_qa_automation.runtime.journal import RunJournal


def test_journal_rejects_preexisting_symlink_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    journal = tmp_path / "run" / "journal.jsonl"
    journal.parent.mkdir()
    try:
        journal.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="journal path.*symlink"):
        RunJournal(journal)

    assert outside.read_text(encoding="utf-8") == "outside\n"


def test_journal_refuses_path_replaced_by_symlink_after_initialization(tmp_path: Path) -> None:
    journal_path = tmp_path / "run" / "journal.jsonl"
    subject = RunJournal(journal_path)
    subject.append("started")
    journal_path.unlink()
    outside = tmp_path / "outside.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        journal_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(RuntimeError, match="became a symlink"):
        subject.append("should-not-write")

    with pytest.raises(RuntimeError, match="became a symlink"):
        subject.verify()

    assert outside.read_text(encoding="utf-8") == "outside\n"
