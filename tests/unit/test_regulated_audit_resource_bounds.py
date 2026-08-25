from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import EvidenceItem, EvidenceKind


def _item(
    run_id: str, *, structured_data: dict[str, object] | None = None, summary: str = "ok"
) -> EvidenceItem:
    return EvidenceItem(
        run_id=run_id,
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="audit-test",
        source_identifier="subject",
        summary=summary,
        structured_data=structured_data or {},
    )


def test_canonical_evidence_hash_survives_manifest_key_reordering(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    item = store.add(_item("run", structured_data={"z": 1, "a": 2, "m": {"y": 3, "b": 4}}))
    line = json.loads((tmp_path / "run" / "audit-log.jsonl").read_text().splitlines()[0])
    assert (
        line["payload"]["content_hash_algorithm"]
        == evidence_module._CANONICAL_EVIDENCE_HASH_ALGORITHM
    )
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored.get(item.id).structured_data == item.structured_data
    assert restored.verify_audit_chain() is True


def test_canonical_hash_matches_sorted_json_reference(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    item = _item("run", structured_data={"z": "雪", "a": 2})
    reference = json.dumps(
        item.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert (
        store._evidence_item_hash(item, canonical=True)
        == "sha256:" + hashlib.sha256(reference).hexdigest()
    )


def test_legacy_hash_path_retains_prior_model_dump_json_semantics(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    item = _item("run", structured_data={"a": 1, "b": 2})
    reference = item.model_dump_json().encode("utf-8")
    assert (
        store._evidence_item_hash(item, canonical=False)
        == "sha256:" + hashlib.sha256(reference).hexdigest()
    )


def test_audit_event_hash_and_line_rendering_match_legacy_json_format(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store._append_audit_event("probe", {"b": 2, "a": "雪"})
    raw = (tmp_path / "run" / "audit-log.jsonl").read_text(encoding="utf-8")
    record = json.loads(raw)
    core = {key: value for key, value in record.items() if key != "event_hash"}
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    assert record["event_hash"] == "sha256:" + hashlib.sha256(canonical).hexdigest()
    assert raw == json.dumps(record, sort_keys=True, default=str) + "\n"


def test_oversized_audit_payload_is_rejected_before_sanitize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_AUDIT_LINE_BYTES", 128)

    def forbidden(_value: object) -> object:
        raise AssertionError("sanitize must not run after failed raw audit preflight")

    monkeypatch.setattr(evidence_module, "sanitize", forbidden)
    with pytest.raises(ValueError, match="line-size bound"):
        store._append_audit_event("probe", {"payload": "x" * 1_000})
    assert store._audit_sequence == 0


def test_regulated_add_does_not_use_model_dump_json_for_content_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)

    def forbidden(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("full model_dump_json materialization is forbidden")

    monkeypatch.setattr(EvidenceItem, "model_dump_json", forbidden)
    item = store.add(_item("run", structured_data={"z": 1, "a": 2}))
    assert store.get(item.id).id == item.id
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored.get(item.id).id == item.id


def test_audit_line_overflow_rolls_back_staged_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_AUDIT_LINE_BYTES", 320)
    with pytest.raises(ValueError, match="line-size bound"):
        store.add(_item("run", summary="x" * 500))
    assert store.all() == []
    assert store._audit_sequence == 0
    path = tmp_path / "run" / "audit-log.jsonl"
    assert not path.exists() or path.read_bytes() == b""


def test_cumulative_audit_limit_rejects_before_append_and_preserves_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    store.add(_item("run", summary="first"))
    path = tmp_path / "run" / "audit-log.jsonl"
    before = path.read_bytes()
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_AUDIT_BYTES", len(before) + 10)
    with pytest.raises(ValueError, match="audit log exceeds persistence size bound"):
        store.add(_item("run", summary="second"))
    assert path.read_bytes() == before
    assert len(store.all()) == 1
    assert store.verify_audit_chain() is True
