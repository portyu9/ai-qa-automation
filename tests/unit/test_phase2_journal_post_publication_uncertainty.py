from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

import ai_qa_automation.runtime.journal as journal_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.journal import RunJournal


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip(
            "post-publication journal authority test requires descriptor-relative authority"
        )


def test_post_publication_parent_revalidation_failure_latches_uncertain_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")

    real_revalidate = journal._revalidate_parent
    calls = 0

    def fail_after_publication(parent_fd: int | None = None) -> None:
        nonlocal calls
        calls += 1
        real_revalidate(parent_fd)
        if calls == 4:
            raise OSError(
                errno.EIO,
                "post-publication parent revalidation became ambiguous",
            )

    monkeypatch.setattr(journal, "_revalidate_parent", fail_after_publication)
    with pytest.raises(
        OSError,
        match="post-publication parent revalidation became ambiguous",
    ):
        journal.append("published-before-parent-revalidation-failure")

    monkeypatch.setattr(journal, "_revalidate_parent", real_revalidate)
    persisted = journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 2
    assert journal.event_count == 1
    assert journal.head_hash == first

    with pytest.raises(OSError, match="run journal write state is uncertain"):
        journal.append("must-not-continue-from-stale-authority")

    assert journal.verify() == persisted


def test_post_publication_parent_close_failure_latches_uncertain_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")
    real_close = os.close
    calls = 0

    def parent_close_then_raise(fd: int) -> None:
        nonlocal calls
        calls += 1
        real_close(fd)
        if calls == 2:
            raise OSError(errno.EIO, "post-publication parent close became ambiguous")

    monkeypatch.setattr(journal_module.os, "close", parent_close_then_raise)
    with pytest.raises(OSError, match="post-publication parent close became ambiguous"):
        journal.append("published-before-parent-close-failure")

    monkeypatch.setattr(journal_module.os, "close", real_close)
    persisted = journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 2
    assert journal.event_count == 1
    assert journal.head_hash == first

    with pytest.raises(OSError, match="run journal write state is uncertain"):
        journal.append("must-not-continue-from-stale-authority")

    assert journal.verify() == persisted


def test_post_publication_parent_close_interrupt_latches_uncertain_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")
    real_close = os.close
    calls = 0

    def parent_close_then_interrupt(fd: int) -> None:
        nonlocal calls
        calls += 1
        real_close(fd)
        if calls == 2:
            raise KeyboardInterrupt("post-publication parent close interrupted")

    monkeypatch.setattr(journal_module.os, "close", parent_close_then_interrupt)
    with pytest.raises(KeyboardInterrupt, match="post-publication parent close interrupted"):
        journal.append("published-before-parent-close-interruption")

    monkeypatch.setattr(journal_module.os, "close", real_close)
    persisted = journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 2
    assert journal.event_count == 1
    assert journal.head_hash == first

    with pytest.raises(OSError, match="run journal write state is uncertain"):
        journal.append("must-not-continue-from-stale-authority")

    assert journal.verify() == persisted


def test_pre_publication_parent_failure_remains_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    path = tmp_path / "journal.jsonl"
    journal = RunJournal(path)
    first = journal.append("first")

    real_revalidate = journal._revalidate_parent
    calls = 0

    def fail_before_publication(parent_fd: int | None = None) -> None:
        nonlocal calls
        calls += 1
        real_revalidate(parent_fd)
        if calls == 2:
            raise OSError(errno.EIO, "pre-publication parent revalidation failed")

    monkeypatch.setattr(journal, "_revalidate_parent", fail_before_publication)
    with pytest.raises(OSError, match="pre-publication parent revalidation failed"):
        journal.append("must-not-publish")

    monkeypatch.setattr(journal, "_revalidate_parent", real_revalidate)
    assert journal.event_count == 1
    assert journal.head_hash == first
    assert journal.verify() == {"valid": True, "events": 1, "head_hash": first}

    second = journal.append("retry-after-pre-publication-failure")
    assert second != first
    assert journal.event_count == 2
    assert journal.head_hash == second
    assert journal.verify() == {"valid": True, "events": 2, "head_hash": second}
