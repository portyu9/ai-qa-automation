from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import ai_qa_automation.runtime.journal as journal_module
import ai_qa_automation.runtime.stale_recovery as stale_recovery_module
import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.io_safety import read_bytes_bounded, sha256_file_bounded
from ai_qa_automation.models import AgentRunState, EvidenceItem, EvidenceKind, EvidenceNature
from ai_qa_automation.runtime.budget import BudgetExceededError, ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import MutationPendingError, RuntimeControl
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore
from ai_qa_automation.tools.repository import RepositoryInspector


def _runtime_control(tmp_path: Path) -> RuntimeControl:
    workspace = tmp_path / "sut"
    workspace.mkdir(exist_ok=True)
    run_dir = tmp_path / "artifacts" / "run-phase1"
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
        lease_id="lease-phase1",
    )


def test_bounded_read_and_hash_enforce_actual_bytes_not_only_preflight(tmp_path: Path) -> None:
    path = tmp_path / "subject.bin"
    path.write_bytes(b"0123456789")

    with pytest.raises(ValueError, match="ingestion limit"):
        read_bytes_bounded(path, max_bytes=9, label="subject")
    with pytest.raises(ValueError, match="ingestion limit"):
        sha256_file_bounded(path, max_bytes=9, label="subject")

    digest, size = sha256_file_bounded(path, max_bytes=10, label="subject")
    assert size == 10
    assert digest == hashlib.sha256(b"0123456789").hexdigest()


def test_state_store_concurrent_saves_leave_one_complete_valid_state(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "run" / "state.json")
    states = [
        AgentRunState(run_id=f"run-{index}", objective=f"objective-{index}", workspace=str(tmp_path))
        for index in range(20)
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(store.save, states))

    loaded = store.load()
    assert (loaded.run_id, loaded.objective) in {
        (item.run_id, item.objective) for item in states
    }
    assert not list((tmp_path / "run").glob(".state.json.*.tmp"))


def test_evidence_concurrent_registration_preserves_manifest_and_audit_chain(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-concurrent", regulated_mode=True)

    def register(index: int) -> str:
        item = store.add(
            EvidenceItem(
                run_id=store.run_id,
                kind=EvidenceKind.SOURCE_OBSERVATION,
                nature=EvidenceNature.OBSERVED_FACT,
                source="concurrency-test",
                source_identifier=str(index),
                summary=f"evidence {index}",
            )
        )
        return item.id

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(register, range(40)))

    assert len(set(ids)) == 40
    assert len(store.all()) == 40
    assert store.verify_audit_chain() is True

    restored = EvidenceStore(tmp_path / "artifacts", "run-concurrent", regulated_mode=True)
    assert len(restored.all()) == 40
    assert restored.verify_audit_chain() is True


def test_run_journal_concurrent_append_remains_linear_and_verifiable(tmp_path: Path) -> None:
    journal = RunJournal(tmp_path / "journal.jsonl", regulated_mode=True, max_events=200)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: journal.append("event", index=index), range(100)))

    status = journal.verify()
    assert status["valid"] is True
    assert status["events"] == 100
    assert journal.event_count == 100


def test_run_journal_byte_budget_fails_closed_before_append(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(journal_module, "_MAX_JOURNAL_BYTES", 320)
    journal = RunJournal(tmp_path / "journal.jsonl", max_events=20)
    journal.append("event", payload="small")
    before = (tmp_path / "journal.jsonl").read_bytes()

    with pytest.raises(BudgetExceededError, match="byte budget"):
        journal.append("event", payload="x" * 300)

    assert (tmp_path / "journal.jsonl").read_bytes() == before
    assert journal.verify()["valid"] is True


def test_runtime_control_allows_only_one_concurrent_pending_mutation(tmp_path: Path) -> None:
    control = _runtime_control(tmp_path)
    paths = ["tests/test_a.py", "tests/test_b.py"]
    for relative in paths:
        target = control.workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("def test_x():\n    assert True\n", encoding="utf-8")

    def prepare(relative: str) -> str:
        try:
            control.prepare_mutation(relative, change_revision_before=0)
        except MutationPendingError:
            return "DENIED"
        return "PREPARED"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(prepare, paths))

    assert sorted(outcomes) == ["DENIED", "PREPARED"]
    assert control.pending_mutation is not None
    control.rollback_pending_mutation(reason="test cleanup")
    assert control.pending_mutation is None


def test_failed_lease_metadata_parse_releases_os_lock(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    first = WorkspaceLease(artifact_root, workspace, "run-a")
    first.path.write_text("{corrupt", encoding="utf-8")

    with pytest.raises(OSError, match="corrupt"):
        first.acquire()

    # Clearing the corrupt bytes is an operator repair. A second acquisition must
    # succeed immediately; otherwise the failed first acquisition leaked its lock.
    first.path.write_text("", encoding="utf-8")
    second = WorkspaceLease(artifact_root, workspace, "run-b").acquire()
    second.release()


def test_invalid_utf8_lease_metadata_fails_closed_and_releases_lock(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    first = WorkspaceLease(artifact_root, workspace, "run-a")
    first.path.write_bytes(b"\xff\xfe\xfd")

    with pytest.raises(OSError, match="valid UTF-8"):
        first.acquire()

    first.path.write_bytes(b"")
    second = WorkspaceLease(artifact_root, workspace, "run-b").acquire()
    second.release()


def test_oversized_lease_metadata_fails_closed_and_releases_lock(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    first = WorkspaceLease(artifact_root, workspace, "run-a")
    first.path.write_text("x" * 70_000, encoding="utf-8")

    with pytest.raises(OSError, match="bounded ingestion"):
        first.acquire()

    first.path.write_text("", encoding="utf-8")
    second = WorkspaceLease(artifact_root, workspace, "run-b").acquire()
    second.release()


def test_stale_recovery_retains_backup_until_runtime_closure_is_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("mutated\n", encoding="utf-8")

    prior_run = artifact_root / "run-old"
    backup = prior_run / "rollback" / "checkout.bin"
    backup.parent.mkdir(parents=True)
    original = b"original\n"
    backup.write_bytes(original)
    runtime_path = prior_run / "runtime.json"
    runtime_payload = {
        "workspace": str(workspace.resolve()),
        "workspace_fingerprint": "fp-after-mutation",
        "journal_event_count": 0,
        "pending_mutation": {
            "relative_path": "tests/test_checkout.py",
            "existed": True,
            "backup_path": str(backup.resolve()),
            "original_sha256": hashlib.sha256(original).hexdigest(),
        },
    }
    runtime_path.write_text(json.dumps(runtime_payload), encoding="utf-8")

    def fail_runtime_close(_path: Path, _payload: dict[str, object]) -> None:
        raise OSError("simulated durable metadata failure")

    monkeypatch.setattr(stale_recovery_module, "atomic_write_json", fail_runtime_close)
    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp-after-mutation",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "durably closed" in str(result["reason"])
    assert target.read_bytes() == original
    assert backup.read_bytes() == original
    persisted = json.loads(runtime_path.read_text(encoding="utf-8"))
    assert persisted["pending_mutation"] is not None


def test_repository_fingerprint_fails_closed_when_changed_file_exceeds_byte_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(repository_module, "_MAX_FINGERPRINT_FILE_BYTES", 32)
    monkeypatch.setattr(repository_module, "_MAX_FINGERPRINT_TOTAL_BYTES", 64)
    target = tmp_path / "tests" / "test_large.py"
    target.parent.mkdir()
    target.write_bytes(b"x" * 33)

    _digest, complete, reasons = RepositoryInspector(tmp_path)._fingerprint(
        "a" * 40,
        " M tests/test_large.py",
        ("tests/test_large.py",),
    )

    assert complete is False
    assert "changed-file-byte-limit-exceeded" in reasons
