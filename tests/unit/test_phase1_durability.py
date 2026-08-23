from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
import ai_qa_automation.runtime.journal as journal_module
import ai_qa_automation.runtime.run_control as run_control_module
import ai_qa_automation.state as state_module
import ai_qa_automation.tools.safe_patch as safe_patch_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import _atomic_write_bytes, atomic_write_json
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.safe_patch import SafeTestPatcher


def test_non_regulated_journal_fsyncs_authoritative_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real_fsync = journal_module.os.fsync

    def record_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(journal_module.os, "fsync", record_fsync)
    RunJournal(tmp_path / "journal.jsonl", regulated_mode=False).append("event")

    assert calls


def test_atomic_runtime_writes_fsync_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(run_control_module, "fsync_directory", lambda path: calls.append(path))

    metadata = tmp_path / "run" / "runtime.json"
    backup = tmp_path / "run" / "rollback" / "backup.bin"
    atomic_write_json(metadata, {"pending_mutation": None})
    _atomic_write_bytes(backup, b"rollback")

    assert calls == [metadata.parent.resolve(), backup.parent.resolve()]


def test_state_store_fsyncs_parent_after_atomic_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = StateStore(tmp_path / "run" / "state.json")
    calls: list[Path] = []
    monkeypatch.setattr(state_module, "fsync_directory", lambda path: calls.append(path))

    store.save(AgentRunState(run_id="run-durable", objective="durability", workspace=str(tmp_path)))

    assert calls == [store.path.parent]


def test_safe_patch_atomic_replace_and_create_fsync_target_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(safe_patch_module, "fsync_directory", lambda path: calls.append(path))
    existing = tmp_path / "tests" / "test_existing.py"
    existing.parent.mkdir()
    existing.write_text("old\n", encoding="utf-8")
    created = existing.parent / "test_created.py"

    SafeTestPatcher._atomic_replace(existing, "new\n")
    SafeTestPatcher._atomic_create(created, "created\n")

    assert existing.read_text(encoding="utf-8") == "new\n"
    assert created.read_text(encoding="utf-8") == "created\n"
    assert calls == [existing.parent, created.parent]


def test_artifact_registration_fsyncs_link_and_manifest_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path] = []
    monkeypatch.setattr(evidence_module, "fsync_directory", lambda path: calls.append(path))
    store = EvidenceStore(tmp_path / "artifacts", "run-durable")

    path, _digest = store.register_artifact(
        relative_path="screens/shot.bin",
        content=b"artifact",
        originating_tool="test",
    )

    assert path == "screens/shot.bin"
    assert (store.run_root / path).read_bytes() == b"artifact"
    assert (store.run_root / "screens") in calls
    assert store.run_root in calls
