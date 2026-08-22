from __future__ import annotations

from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import EvidenceItem, EvidenceKind


def observed(run_id: str, *, summary: str = "observed") -> EvidenceItem:
    return EvidenceItem(
        run_id=run_id,
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="test",
        summary=summary,
    )


def test_rejected_regulated_audit_append_does_not_advance_sequence_or_keep_item(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-audit-bound", regulated_mode=True)
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_AUDIT_BYTES", 1)

    with pytest.raises(ValueError, match="audit log exceeds"):
        store.add(observed(store.run_id))

    assert store._audit_sequence == 0
    assert store._audit_previous_hash == "GENESIS"
    assert store.all() == []
    audit_path = store.run_root / "audit-log.jsonl"
    assert not audit_path.exists() or audit_path.read_bytes() == b""


def test_manifest_preflight_rejection_removes_unregistered_artifact_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-manifest-bound")
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_MANIFEST_BYTES", 1)

    with pytest.raises(ValueError, match="manifest exceeds"):
        store.register_artifact(
            relative_path="logs/result.bin",
            content=b"result",
            originating_tool="test",
        )

    assert store._artifacts == {}
    assert not (store.run_root / "logs" / "result.bin").exists()


def test_cumulative_artifact_limit_is_checked_before_file_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-artifact-bound")
    monkeypatch.setattr(evidence_module, "_MAX_TOTAL_ARTIFACT_BYTES", 3)

    with pytest.raises(ValueError, match="cumulative persistence byte limit"):
        store.register_artifact(
            relative_path="logs/result.bin",
            content=b"1234",
            originating_tool="test",
        )

    assert not (store.run_root / "logs" / "result.bin").exists()


def test_evidence_count_limit_preserves_existing_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-evidence-count")
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_COUNT", 1)
    first = store.add(observed(store.run_id, summary="first"))

    with pytest.raises(ValueError, match="evidence registry exceeds"):
        store.add(observed(store.run_id, summary="second"))

    assert [item.id for item in store.all()] == [first.id]
