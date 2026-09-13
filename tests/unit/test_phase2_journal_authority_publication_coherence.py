from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("journal authority publication test requires descriptor-relative authority")


def _make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-journal-authority-publication"
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=20,
            max_network_calls=20,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-journal-authority-publication",
    )


def _fail_next_append_after_publication(
    journal: RunJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> object:
    real_revalidate = journal._revalidate_parent
    calls = 0

    def fail_after_publication(parent_fd: int | None = None) -> None:
        nonlocal calls
        calls += 1
        real_revalidate(parent_fd)
        if calls == 4:
            raise OSError(errno.EIO, "post-publication journal authority became ambiguous")

    monkeypatch.setattr(journal, "_revalidate_parent", fail_after_publication)
    return real_revalidate


def test_runtime_persist_rejects_uncertain_journal_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    control = _make_control(tmp_path)
    first = control.journal.append("first")
    control.persist()
    durable_before = control.metadata_path.read_bytes()

    real_revalidate = _fail_next_append_after_publication(control.journal, monkeypatch)
    with pytest.raises(OSError, match="post-publication journal authority became ambiguous"):
        control.journal.append("published-but-not-adopted")
    monkeypatch.setattr(control.journal, "_revalidate_parent", real_revalidate)

    assert control.journal.event_count == 1
    assert control.journal.head_hash == first
    persisted = control.journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 2

    with pytest.raises(OSError, match="run journal authority state is uncertain"):
        control.persist()

    assert control.metadata_path.read_bytes() == durable_before


def test_prepare_mutation_uncertain_journal_keeps_durable_pending_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    control = _make_control(tmp_path)
    target = control.workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    first = control.journal.append("first")

    real_revalidate = _fail_next_append_after_publication(control.journal, monkeypatch)
    with pytest.raises(RuntimeError, match="pending metadata could not be cleared"):
        control.prepare_mutation("tests/test_checkout.py")
    monkeypatch.setattr(control.journal, "_revalidate_parent", real_revalidate)

    assert control.pending_mutation is not None
    assert control.pending_mutation.relative_path == "tests/test_checkout.py"
    assert control.pending_mutation.backup_path is not None
    assert Path(control.pending_mutation.backup_path).is_file()

    metadata = json.loads(control.metadata_path.read_text(encoding="utf-8"))
    pending = metadata["pending_mutation"]
    assert isinstance(pending, dict)
    assert pending["relative_path"] == "tests/test_checkout.py"
    assert metadata["journal_event_count"] == 1
    assert metadata["journal_head_hash"] == first

    persisted = control.journal.verify()
    assert persisted["valid"] is True
    assert persisted["events"] == 2
    assert target.read_text(encoding="utf-8") == "before\n"
