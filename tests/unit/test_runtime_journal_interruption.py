from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import ai_qa_automation.runtime.journal as journal_module
from ai_qa_automation.runtime.journal import RunJournal


def test_journal_partial_write_is_rolled_back_without_losing_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")
    before = path.read_bytes()
    real_write = os.write
    calls = 0

    def interrupted_write(fd: int, data: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            partial = max(1, len(data) // 2)
            return real_write(fd, data[:partial])
        raise OSError(errno.EIO, "injected short-write interruption")

    monkeypatch.setattr(journal_module.os, "write", interrupted_write)
    with pytest.raises(OSError, match="injected short-write interruption"):
        journal.append("interrupted")

    assert path.read_bytes() == before
    assert journal.event_count == 1
    assert journal.head_hash == first
    assert journal.verify() == {"valid": True, "events": 1, "head_hash": first}

    monkeypatch.setattr(journal_module.os, "write", real_write)
    second = journal.append("second")
    assert journal.verify() == {"valid": True, "events": 2, "head_hash": second}


def test_journal_fsync_failure_rolls_back_completed_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")
    before = path.read_bytes()
    real_fsync = os.fsync
    calls = 0

    def interrupted_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError(errno.EIO, "injected fsync interruption")
        real_fsync(fd)

    monkeypatch.setattr(journal_module.os, "fsync", interrupted_fsync)
    with pytest.raises(OSError, match="injected fsync interruption"):
        journal.append("interrupted")

    assert path.read_bytes() == before
    assert journal.event_count == 1
    assert journal.head_hash == first
    assert journal.verify() == {"valid": True, "events": 1, "head_hash": first}


def test_journal_failed_rollback_latches_uncertain_write_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")
    real_write = os.write
    real_ftruncate = os.ftruncate
    calls = 0

    def interrupted_write(fd: int, data: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            partial = max(1, len(data) // 2)
            return real_write(fd, data[:partial])
        raise OSError(errno.EIO, "injected short-write interruption")

    def failed_rollback(_fd: int, _length: int) -> None:
        raise OSError(errno.EIO, "injected rollback failure")

    monkeypatch.setattr(journal_module.os, "write", interrupted_write)
    monkeypatch.setattr(journal_module.os, "ftruncate", failed_rollback)
    with pytest.raises(OSError, match="rollback could not be durably proven"):
        journal.append("interrupted")

    assert journal.event_count == 1
    assert journal.head_hash == first
    assert journal.verify()["valid"] is False

    monkeypatch.setattr(journal_module.os, "write", real_write)
    monkeypatch.setattr(journal_module.os, "ftruncate", real_ftruncate)
    with pytest.raises(OSError, match="write state is uncertain"):
        journal.append("must-not-continue")


def test_journal_uncertain_descriptor_close_latches_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    real_close = os.close
    calls = 0

    def uncertain_close(fd: int) -> None:
        nonlocal calls
        calls += 1
        real_close(fd)
        if calls == 1:
            raise OSError(errno.EIO, "injected close uncertainty")

    monkeypatch.setattr(journal_module.os, "close", uncertain_close)
    with pytest.raises(OSError, match="descriptor close could not be proven"):
        journal.append("durably-written-but-close-uncertain")

    assert journal.event_count == 0
    assert journal.head_hash is None
    persisted = journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 1

    monkeypatch.setattr(journal_module.os, "close", real_close)
    with pytest.raises(OSError, match="write state is uncertain"):
        journal.append("must-not-continue")
