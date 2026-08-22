from __future__ import annotations

import json
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


def test_run_id_symlink_alias_is_rejected_even_when_target_stays_under_artifact_root(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    actual = artifact_root / "actual"
    actual.mkdir(parents=True)
    alias = artifact_root / "alias"
    try:
        alias.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        EvidenceStore(artifact_root, "alias/run-123")


def test_valid_nested_run_id_remains_confined(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    store = EvidenceStore(artifact_root, "runs/run-123")

    assert store.run_root == (artifact_root / "runs" / "run-123").resolve()
    assert artifact_root.resolve() in store.run_root.parents


def test_artifact_symlink_directory_is_rejected_even_when_resolution_would_be_bounded(
    tmp_path: Path,
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-safe")
    actual = store.run_root / "actual"
    actual.mkdir()
    link = store.run_root / "browser"
    try:
        link.symlink_to(actual, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        store.register_artifact(
            relative_path="browser/screenshot.png",
            content=b"sensitive",
            originating_tool="browser",
        )

    assert not (actual / "screenshot.png").exists()


def test_artifact_symlink_directory_escape_is_rejected(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-safe")
    outside = tmp_path / "outside"
    outside.mkdir()
    link = store.run_root / "browser"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        store.register_artifact(
            relative_path="browser/screenshot.png",
            content=b"sensitive",
            originating_tool="browser",
        )

    assert not (outside / "screenshot.png").exists()


@pytest.mark.parametrize("relative_path", ["", ".", "../escape.txt", "nested/../../escape.txt"])
def test_artifact_path_must_be_non_traversing_relative_path(
    tmp_path: Path, relative_path: str
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-safe")
    with pytest.raises(ValueError, match="relative path"):
        store.register_artifact(
            relative_path=relative_path,
            content=b"data",
            originating_tool="test",
        )


def test_absolute_artifact_path_is_rejected_even_when_it_points_inside_run_root(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-safe")
    absolute_inside = str((store.run_root / "inside.txt").resolve())

    with pytest.raises(ValueError, match="relative path"):
        store.register_artifact(
            relative_path=absolute_inside,
            content=b"data",
            originating_tool="test",
        )

    assert not (store.run_root / "inside.txt").exists()


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


def test_manifest_duplicate_evidence_ids_are_rejected_on_reopen(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "run-a")
    item = store.add(
        EvidenceItem(
            id="ev-fixed",
            run_id="run-a",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="original",
        )
    )
    manifest_path = store.run_root / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"].append(item.model_dump(mode="json"))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate evidence ids"):
        EvidenceStore(root, "run-a")
