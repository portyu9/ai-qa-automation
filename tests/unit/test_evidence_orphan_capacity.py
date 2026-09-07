from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.evidence as evidence_module
from ai_qa_automation.evidence import EvidenceStore


def _leave_durable_orphan(
    store: EvidenceStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    relative_path: str,
    content: bytes,
) -> Path:
    def fail_manifest_closure() -> None:
        raise OSError("injected manifest closure failure")

    monkeypatch.setattr(store, "_flush_manifest", fail_manifest_closure)
    with pytest.raises(OSError, match="injected manifest closure failure"):
        store.register_artifact(
            relative_path=relative_path,
            content=content,
            originating_tool="test",
        )

    orphan = store.run_root / relative_path
    assert orphan.read_bytes() == content
    assert store._artifacts == {}
    return orphan


def test_durable_orphan_counts_against_byte_capacity_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setattr(evidence_module, "_MAX_TOTAL_ARTIFACT_BYTES", 8)

    first = EvidenceStore(artifact_root, "run-orphan-byte-bound")
    orphan = _leave_durable_orphan(
        first,
        monkeypatch,
        relative_path="logs/orphan.bin",
        content=b"12345",
    )
    assert not (first.run_root / "evidence-manifest.json").exists()

    restarted = EvidenceStore(artifact_root, first.run_id)
    rejected = restarted.run_root / "logs" / "rejected.bin"
    with pytest.raises(ValueError, match="cumulative persistence byte limit"):
        restarted.register_artifact(
            relative_path="logs/rejected.bin",
            content=b"6789",
            originating_tool="test",
        )

    assert orphan.read_bytes() == b"12345"
    assert not rejected.exists()


def test_existing_over_limit_orphan_fails_closed_during_store_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    first = EvidenceStore(artifact_root, "run-restore-byte-bound")
    orphan = first.run_root / "orphan.bin"
    orphan.write_bytes(b"12345")
    monkeypatch.setattr(evidence_module, "_MAX_TOTAL_ARTIFACT_BYTES", 4)

    with pytest.raises(ValueError, match="cumulative persistence byte limit"):
        EvidenceStore(artifact_root, first.run_id)

    assert orphan.read_bytes() == b"12345"


def test_durable_orphan_counts_against_file_capacity_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    monkeypatch.setattr(evidence_module, "_MAX_ARTIFACT_COUNT", 1)

    first = EvidenceStore(artifact_root, "run-orphan-count-bound")
    orphan = _leave_durable_orphan(
        first,
        monkeypatch,
        relative_path="orphan.bin",
        content=b"one",
    )

    restarted = EvidenceStore(artifact_root, first.run_id)
    rejected = restarted.run_root / "rejected.bin"
    with pytest.raises(ValueError, match="persistence count limit"):
        restarted.register_artifact(
            relative_path="rejected.bin",
            content=b"two",
            originating_tool="test",
        )

    assert orphan.read_bytes() == b"one"
    assert not rejected.exists()


def test_capacity_scan_excludes_authorized_shared_run_control_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    first = EvidenceStore(artifact_root, "run-control-files")
    for name in ("state.json", "runtime.json", "journal.jsonl"):
        (first.run_root / name).write_bytes(b"control-state")
    monkeypatch.setattr(evidence_module, "_MAX_TOTAL_ARTIFACT_BYTES", 4)

    store = EvidenceStore(
        artifact_root,
        first.run_id,
        expected_run_root_identity=first.run_root_identity,
    )
    path, digest = store.register_artifact(
        relative_path="result.bin",
        content=b"1234",
        originating_tool="test",
    )

    assert path == "result.bin"
    assert digest == store.hash_bytes(b"1234")
    assert (store.run_root / path).read_bytes() == b"1234"


def test_unowned_control_name_is_not_exempt_from_physical_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    first = EvidenceStore(artifact_root, "run-unowned-control-name")
    (first.run_root / "audit-log.jsonl").write_bytes(b"12345")
    monkeypatch.setattr(evidence_module, "_MAX_TOTAL_ARTIFACT_BYTES", 4)

    with pytest.raises(ValueError, match="cumulative persistence byte limit"):
        EvidenceStore(artifact_root, first.run_id)


def test_reserved_run_control_path_cannot_be_registered_as_artifact(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-reserved-control")

    with pytest.raises(ValueError, match="reserved run persistence control file"):
        store.register_artifact(
            relative_path="audit-log.jsonl",
            content=b"payload",
            originating_tool="test",
        )

    assert not (store.run_root / "audit-log.jsonl").exists()


def test_capacity_scan_enforces_tree_entry_bound_before_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-tree-bound")
    monkeypatch.setattr(evidence_module, "_MAX_ARTIFACT_TREE_ENTRIES", 2)
    for name in ("one", "two", "three"):
        (store.run_root / name).mkdir()

    rejected = store.run_root / "rejected.bin"
    with pytest.raises(ValueError, match="tree exceeds persistence entry limit"):
        store.register_artifact(
            relative_path="rejected.bin",
            content=b"x",
            originating_tool="test",
        )

    assert not rejected.exists()


@pytest.mark.skipif(
    os.name == "nt",
    reason="symlink creation is not reliably available on Windows CI",
)
def test_capacity_scan_fails_closed_on_unregistered_symlink(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    store = EvidenceStore(artifact_root, "run-orphan-symlink")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    (store.run_root / "orphan-link").symlink_to(outside)

    rejected = store.run_root / "rejected.bin"
    with pytest.raises(ValueError, match="symlink"):
        store.register_artifact(
            relative_path="rejected.bin",
            content=b"x",
            originating_tool="test",
        )

    assert outside.read_bytes() == b"outside"
    assert not rejected.exists()


@pytest.mark.skipif(os.name == "nt", reason="FIFO creation is unavailable on Windows")
def test_capacity_scan_fails_closed_on_non_regular_entry(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "artifacts", "run-orphan-fifo")
    fifo = store.run_root / "orphan-fifo"
    os.mkfifo(fifo)

    rejected = store.run_root / "rejected.bin"
    with pytest.raises(ValueError, match="unexpected non-regular entry"):
        store.register_artifact(
            relative_path="rejected.bin",
            content=b"x",
            originating_tool="test",
        )

    assert fifo.exists()
    assert not rejected.exists()
