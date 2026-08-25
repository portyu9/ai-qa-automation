from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
import ai_qa_automation.state as state_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.io_safety import JsonSerializationBoundsError, iter_json_text_bounded
from ai_qa_automation.models import AgentRunState, EvidenceItem, EvidenceKind
from ai_qa_automation.state import StateStore


def test_json_encoder_stops_at_byte_ceiling_without_full_text() -> None:
    chunks: list[str] = []
    with pytest.raises(JsonSerializationBoundsError):
        for chunk in iter_json_text_bounded(
            {"payload": "x" * 10_000},
            max_bytes=128,
            label="test json",
            indent=2,
        ):
            chunks.append(chunk)
    assert sum(len(chunk.encode("utf-8")) for chunk in chunks) <= 128
    assert "".join(chunks) != json.dumps({"payload": "x" * 10_000}, indent=2)


def test_oversized_string_is_denied_before_json_encoder_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json as json_module

    def forbidden(*_args, **_kwargs):
        raise AssertionError("JSONEncoder.iterencode must not run after failed preflight")

    monkeypatch.setattr(json_module.JSONEncoder, "iterencode", forbidden)
    with pytest.raises(JsonSerializationBoundsError) as exc_info:
        list(
            iter_json_text_bounded(
                {"payload": "x" * 10_000},
                max_bytes=128,
                label="test json",
                indent=2,
            )
        )
    assert exc_info.value.code == "bytes"


def test_state_overflow_preserves_previous_durable_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "state.json")
    original = AgentRunState(objective="original", workspace=str(tmp_path))
    store.save(original)
    before = store.path.read_bytes()

    monkeypatch.setattr(state_module, "_MAX_STATE_BYTES", 512)
    oversized = AgentRunState(
        objective="oversized",
        workspace=str(tmp_path),
        observations=["x" * 2_000],
    )
    with pytest.raises(ValueError, match="canonical state exceeds persistence size bound"):
        store.save(oversized)

    assert store.path.read_bytes() == before
    monkeypatch.setattr(state_module, "_MAX_STATE_BYTES", 16_000_000)
    assert store.load().objective == "original"
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_state_save_no_longer_uses_full_model_dump_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = AgentRunState(objective="bounded", workspace=str(tmp_path))
    store = StateStore(tmp_path / "state.json")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("full model_dump_json must not be used by StateStore.save")

    monkeypatch.setattr(AgentRunState, "model_dump_json", forbidden)
    store.save(state)
    assert json.loads(store.path.read_text())["objective"] == "bounded"


def test_manifest_overflow_rolls_back_uncommitted_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_MANIFEST_BYTES", 1_300)
    store = EvidenceStore(tmp_path / "artifacts", "run")
    first = store.add(
        EvidenceItem(
            id="ev-first",
            run_id="run",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="f" * 100,
        )
    )
    manifest_path = tmp_path / "artifacts" / "run" / "evidence-manifest.json"
    before = manifest_path.read_bytes()

    with pytest.raises(ValueError, match="evidence manifest exceeds persistence size bound"):
        store.add(
            EvidenceItem(
                id="ev-too-large",
                run_id="run",
                kind=EvidenceKind.SOURCE_OBSERVATION,
                source="test",
                summary="x" * 500,
            )
        )

    assert store.get(first.id).summary == "f" * 100
    with pytest.raises(KeyError):
        store.get("ev-too-large")
    assert manifest_path.read_bytes() == before
    assert not list(manifest_path.parent.glob(".evidence-manifest.*.tmp"))


def test_manifest_streaming_preserves_existing_json_bytes(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run")
    store.add(
        EvidenceItem(
            id="ev-unicode",
            run_id="run",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="café",
        )
    )
    actual = (tmp_path / "artifacts" / "run" / "evidence-manifest.json").read_text()
    expected_data = {
        "run_id": store.run_id,
        "regulated_mode": store.regulated_mode,
        "evidence": [item.model_dump(mode="json") for item in store._items.values()],
        "artifacts": [item.model_dump(mode="json") for item in store._artifacts.values()],
        "sanitization_status": "SANITIZED",
    }
    assert actual == json.dumps(expected_data, indent=2, sort_keys=True)
    assert "caf\\u00e9" in actual


def test_state_preflight_rejects_oversized_raw_field_before_pydantic_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(state_module, "_MAX_STATE_BYTES", 256)
    state = AgentRunState(
        objective="bounded",
        workspace=str(tmp_path),
        observations=["x" * 2_000],
    )
    store = StateStore(tmp_path / "state.json")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Pydantic field conversion must not run after failed raw preflight")

    monkeypatch.setattr(AgentRunState, "model_dump", forbidden)
    with pytest.raises(ValueError, match="canonical state exceeds persistence size bound"):
        store.save(state)
    assert not store.path.exists()


def test_evidence_preflight_rejects_oversized_raw_item_before_sanitize_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evidence_module, "_MAX_EVIDENCE_MANIFEST_BYTES", 512)
    store = EvidenceStore(tmp_path / "artifacts", "run")
    item = EvidenceItem(
        id="ev-oversized",
        run_id="run",
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="test",
        summary="x" * 2_000,
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("EvidenceItem.model_dump must not run after failed raw preflight")

    monkeypatch.setattr(EvidenceItem, "model_dump", forbidden)
    with pytest.raises(ValueError, match="evidence item exceeds persistence size bound"):
        store.add(item)
    with pytest.raises(KeyError):
        store.get(item.id)


def test_state_streaming_preserves_existing_pydantic_json_bytes(tmp_path: Path) -> None:
    state = AgentRunState(
        objective="café Ω",
        workspace=str(tmp_path),
        observations=["line one\nline two"],
    )
    expected = state.model_dump_json(indent=2)
    store = StateStore(tmp_path / "state.json")
    store.save(state)
    assert store.path.read_text(encoding="utf-8") == expected


def test_regulated_manifest_and_audit_reopen_after_streaming_write(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "regulated", regulated_mode=True)
    item = store.add(
        EvidenceItem(
            id="ev-regulated",
            run_id="regulated",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="durable",
        )
    )
    store.register_artifact(
        relative_path="result.txt",
        content=b"result",
        originating_tool="test",
    )
    assert store.verify_audit_chain()

    reopened = EvidenceStore(root, "regulated", regulated_mode=True)
    assert reopened.verify_audit_chain()
    assert reopened.get(item.id).summary == "durable"
