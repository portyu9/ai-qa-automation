from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import ai_qa_automation.runtime.run_control as run_control_module
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl


def _make_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_dir = tmp_path / "artifacts" / "run-journal-atomicity"
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
        lease_id="lease-journal-atomicity",
    )


def _forbid_split_authority_read(_journal: RunJournal) -> int:
    raise AssertionError(
        "runtime snapshot must not assemble journal authority from split properties"
    )


def test_runtime_snapshot_uses_one_journal_authority_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _make_control(tmp_path)
    head = control.journal.append("first")

    monkeypatch.setattr(
        RunJournal,
        "event_count",
        property(_forbid_split_authority_read),
    )
    monkeypatch.setattr(
        RunJournal,
        "head_hash",
        property(_forbid_split_authority_read),
    )

    snapshot = control.snapshot()

    assert snapshot["journal_event_count"] == 1
    assert snapshot["journal_head_hash"] == head


def test_runtime_persist_holds_journal_authority_through_metadata_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _make_control(tmp_path)
    head = control.journal.append("first")
    original_binding = control.journal.authority_binding
    binding_depth = 0
    published: dict[str, Any] = {}

    @contextmanager
    def tracked_binding() -> Iterator[tuple[int, str | None]]:
        nonlocal binding_depth
        with original_binding() as authority:
            binding_depth += 1
            try:
                yield authority
            finally:
                binding_depth -= 1

    def guarded_atomic_write_json(
        path: Path,
        payload: dict[str, Any],
        *,
        expected_parent_identity: tuple[int, int] | None = None,
    ) -> None:
        del path, expected_parent_identity
        assert binding_depth >= 1
        published.update(payload)

    monkeypatch.setattr(control.journal, "authority_binding", tracked_binding)
    monkeypatch.setattr(run_control_module, "atomic_write_json", guarded_atomic_write_json)

    control.persist()

    assert binding_depth == 0
    assert published["journal_event_count"] == 1
    assert published["journal_head_hash"] == head
