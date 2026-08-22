from __future__ import annotations

from pathlib import Path

import pytest

from ai_qa_automation.evidence import EvidenceStore


def test_evidence_store_rejects_symlinked_manifest_control_file(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    run = root / "run-owned"
    run.mkdir(parents=True)
    outside = tmp_path / "outside-manifest.json"
    outside.write_text("{}", encoding="utf-8")
    manifest = run / "evidence-manifest.json"
    try:
        manifest.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="control file.*symlink"):
        EvidenceStore(root, "run-owned")


def test_regulated_reopen_rejects_artifact_replaced_by_symlink_even_with_same_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "run-regulated", regulated_mode=True)
    relative, _ = store.register_artifact(
        relative_path="browser/context.bin",
        content=b"same-bytes",
        originating_tool="test",
    )
    artifact = store.run_root / relative
    outside = tmp_path / "outside.bin"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    try:
        artifact.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="artifact ownership"):
        EvidenceStore(root, "run-regulated", regulated_mode=True)


def test_regulated_store_rejects_audit_log_replaced_by_symlink_before_append(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "run-audit", regulated_mode=True)
    audit = store.run_root / "audit-log.jsonl"
    outside = tmp_path / "outside-audit.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    if audit.exists():
        audit.unlink()
    try:
        audit.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="control file.*symlink"):
        store.register_artifact(
            relative_path="logs/result.txt",
            content=b"result",
            originating_tool="test",
        )

    assert outside.read_text(encoding="utf-8") == "outside\n"
