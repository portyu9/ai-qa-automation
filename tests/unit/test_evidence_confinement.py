from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import EvidenceItem, EvidenceKind


@pytest.mark.parametrize("run_id", ["", ".", "..", "../escape", "nested/../../escape"])
def test_run_id_cannot_escape_or_alias_artifact_root(tmp_path: Path, run_id: str) -> None:
    artifact_root = tmp_path / "artifacts"

    with pytest.raises(ValueError, match="escapes artifact root"):
        EvidenceStore(artifact_root, run_id)

    assert not (tmp_path / "escape").exists()


def test_absolute_run_id_is_rejected(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    absolute = str((tmp_path / "absolute-escape").resolve())

    with pytest.raises(ValueError, match="escapes artifact root"):
        EvidenceStore(artifact_root, absolute)

    assert not (tmp_path / "absolute-escape").exists()


def test_valid_nested_run_id_remains_confined(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    store = EvidenceStore(artifact_root, "runs/run-123")

    assert store.run_root == (artifact_root / "runs" / "run-123").resolve()
    assert artifact_root.resolve() in store.run_root.parents


def test_artifact_symlink_directory_escape_is_rejected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = store.run_root / "browser"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="escapes run root"):
        store.register_artifact(
            relative_path="browser/screenshot.png",
            content=b"sensitive",
            originating_tool="browser",
        )

    assert not (outside / "screenshot.png").exists()


def test_evidence_run_id_mismatch_is_rejected_before_manifest_mutation(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-a")
    wrong = EvidenceItem(
        id="ev-wrong-run",
        run_id="run-b",
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="test",
        summary="must not be persisted",
    )

    with pytest.raises(ValueError, match="run_id does not match"):
        store.add(wrong)

    assert store.all() == []
    assert not (store.run_root / "evidence-manifest.json").exists()


def test_duplicate_evidence_id_cannot_replace_existing_record(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-a")
    original = EvidenceItem(
        id="ev-fixed",
        run_id="run-a",
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="test",
        summary="original",
    )
    store.add(original)

    with pytest.raises(ValueError, match="immutable"):
        store.add(original.model_copy(update={"summary": "replacement"}))

    assert store.get("ev-fixed").summary == "original"


def test_duplicate_artifact_path_cannot_replace_existing_bytes(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-a")
    path, digest = store.register_artifact(
        relative_path="browser/result.txt",
        content=b"first",
        originating_tool="test",
    )

    with pytest.raises(FileExistsError, match="immutable"):
        store.register_artifact(
            relative_path="browser/result.txt",
            content=b"second",
            originating_tool="test",
        )

    assert (store.run_root / path).read_bytes() == b"first"
    assert store.hash_bytes(b"first") == digest
