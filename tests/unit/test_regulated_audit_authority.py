from __future__ import annotations

import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.attestation as attestation_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.models import EvidenceItem, EvidenceKind, EvidenceNature
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.journal import RunJournal


def _item(run_id: str, suffix: str) -> EvidenceItem:
    return EvidenceItem(
        run_id=run_id,
        kind=EvidenceKind.SOURCE_OBSERVATION,
        nature=EvidenceNature.OBSERVED_FACT,
        source="issue-88-test",
        source_identifier=suffix,
        summary=f"evidence {suffix}",
        structured_data={"suffix": suffix},
    )


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _prepare_run(root: Path, *, regulated: bool) -> tuple[Path, EvidenceStore]:
    run_dir = root / "run-1"
    workspace = root / "sut"
    workspace.mkdir(parents=True)
    _write_json(
        run_dir / "state.json",
        {
            "run_id": "run-1",
            "objective": "verify regulated audit authority",
            "workspace": str(workspace.resolve()),
            "terminal_status": "NOT_VERIFIED",
            "terminal_reason": "fixture",
            "target_git_sha": "abc123",
            "agent_version": "0.1.0",
            "model_id": "claude",
            "sdk_version": "sdk",
            "policy_version": "policy",
            "tool_schema_version": "tools",
            "configuration_version": "cfg",
            "change_revision": 1,
            "validation_results": [],
        },
    )
    RunJournal(run_dir / "journal.jsonl").append("run_started", run_id="run-1")
    journal = RunJournal(run_dir / "journal.jsonl").verify()
    status = workspace.stat(follow_symlinks=False)
    _write_json(
        run_dir / "runtime.json",
        {
            "workspace_fingerprint": "fp-1",
            "journal_event_count": journal["events"],
            "journal_head_hash": journal["head_hash"],
            "pending_mutation": None,
            "workspace": str(workspace.resolve()),
            "workspace_root_identity": {"device": status.st_dev, "inode": status.st_ino},
        },
    )
    store = EvidenceStore(root, "run-1", regulated_mode=regulated)
    store.add(_item("run-1", "first"))
    return run_dir, store


def test_replaced_regular_audit_file_is_rejected_before_mutation(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative final-file identity authority is unavailable")
    run_dir, store = _prepare_run(tmp_path, regulated=True)
    audit_path = run_dir / "audit-log.jsonl"
    manifest_path = run_dir / "evidence-manifest.json"
    audit_path.rename(run_dir / "audit-original.jsonl")
    replacement = b'{"replacement":true}\n'
    audit_path.write_bytes(replacement)
    manifest_before = manifest_path.read_bytes()

    with pytest.raises(ValueError, match="changed identity since authorization"):
        store.add(_item("run-1", "second"))

    assert audit_path.read_bytes() == replacement
    assert manifest_path.read_bytes() == manifest_before
    assert [item.source_identifier for item in store.all()] == ["first"]
    with pytest.raises(OSError, match="write state is uncertain"):
        store.add(_item("run-1", "blocked"))


def test_regulated_attestation_binds_valid_audit_subject(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("full attestation authority is unavailable")
    run_dir, _store = _prepare_run(tmp_path, regulated=True)

    attestation = build_run_attestation(run_dir)
    audit = attestation["integrity"]["regulated_audit"]

    assert attestation["integrity"]["integrity_verified"] is True
    assert audit["applicable"] is True
    assert audit["valid"] is True
    assert audit["registry_reconciled"] is True
    assert audit["final_file_identity_continuity_enforced"] is True
    assert audit["events"] == 1
    assert str(audit["head_hash"]).startswith("sha256:")
    assert str(audit["content_hash"]).startswith("sha256:")
    assert attestation["integrity"]["persisted_subjects"]["audit-log.jsonl"] is not None


def test_missing_regulated_audit_file_cannot_attest_green(tmp_path: Path) -> None:
    run_dir, _store = _prepare_run(tmp_path, regulated=True)
    (run_dir / "audit-log.jsonl").unlink()

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["regulated_audit"]["valid"] is False
    assert "missing" in attestation["integrity"]["regulated_audit"]["reason"]
    assert attestation["integrity"]["persisted_subjects"]["audit-log.jsonl"] is None


@pytest.mark.parametrize("field", ["events", "last_event_hash", "content_hash"])
def test_mismatched_regulated_manifest_audit_binding_cannot_attest_green(
    tmp_path: Path,
    field: str,
) -> None:
    run_dir, _store = _prepare_run(tmp_path, regulated=True)
    manifest_path = run_dir / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if field == "events":
        manifest["audit_log"][field] += 1
    else:
        manifest["audit_log"][field] = "sha256:" + "0" * 64
    _write_json(manifest_path, manifest)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["regulated_audit"]["valid"] is False
    assert "manifest binding" in attestation["integrity"]["regulated_audit"]["reason"]


def test_corrupted_regulated_audit_chain_cannot_attest_green(tmp_path: Path) -> None:
    run_dir, store = _prepare_run(tmp_path, regulated=True)
    store.add(_item("run-1", "second"))
    audit_path = run_dir / "audit-log.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    lines.reverse()
    audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["regulated_audit"]["valid"] is False
    assert "sequence" in attestation["integrity"]["regulated_audit"]["reason"]


def test_regulated_registry_audit_reconciliation_is_attested(tmp_path: Path) -> None:
    run_dir, _store = _prepare_run(tmp_path, regulated=True)
    manifest_path = run_dir / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"][0]["summary"] = "tampered but schema-valid"
    _write_json(manifest_path, manifest)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["manifest"]["valid"] is True
    assert attestation["integrity"]["regulated_audit"]["valid"] is False
    assert (
        "evidence integrity check failed"
        in attestation["integrity"]["regulated_audit"]["reason"]
    )
    assert attestation["integrity"]["integrity_verified"] is False


def test_non_regulated_attestation_does_not_require_or_fabricate_audit_authority(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("full attestation authority is unavailable")
    run_dir, _store = _prepare_run(tmp_path, regulated=False)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is True
    assert "regulated_audit" not in attestation["integrity"]
    assert "audit-log.jsonl" not in attestation["integrity"]["persisted_subjects"]


def test_non_regulated_attestation_ignores_stray_audit_symlink(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("full attestation authority is unavailable")
    run_dir, _store = _prepare_run(tmp_path, regulated=False)
    outside = tmp_path / "outside-audit.jsonl"
    outside.write_text("outside\n", encoding="utf-8")
    try:
        (run_dir / "audit-log.jsonl").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is True
    assert "regulated_audit" not in attestation["integrity"]
    assert "audit-log.jsonl" not in attestation["integrity"]["persisted_subjects"]


def test_malformed_regulated_audit_binding_remains_applicable_and_fails_closed(
    tmp_path: Path,
) -> None:
    run_dir, _store = _prepare_run(tmp_path, regulated=True)
    manifest_path = run_dir / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["audit_log"].pop("content_hash")
    _write_json(manifest_path, manifest)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["manifest"]["valid"] is False
    assert attestation["integrity"]["regulated_audit"]["applicable"] is True
    assert attestation["integrity"]["regulated_audit"]["valid"] is False
    assert attestation["integrity"]["integrity_verified"] is False


def test_regulated_attestation_fallback_does_not_claim_file_identity_continuity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir, _store = _prepare_run(tmp_path, regulated=True)
    monkeypatch.setattr(
        attestation_module,
        "descriptor_relative_authority_supported",
        lambda: False,
    )

    attestation = build_run_attestation(run_dir)

    assert (
        attestation["integrity"]["regulated_audit"]["final_file_identity_continuity_enforced"]
        is False
    )
    assert attestation["integrity"]["integrity_verified"] is False


def _capture_audit_descriptor(monkeypatch: pytest.MonkeyPatch) -> dict[str, int | None]:
    import ai_qa_automation.fs_authority as fs_authority_module

    real_open = fs_authority_module.os.open
    captured: dict[str, int | None] = {"fd": None}

    def capture_open(
        path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is None:
            fd = real_open(path, flags, mode)
        else:
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
        if str(path) == "audit-log.jsonl":
            captured["fd"] = fd
        return fd

    monkeypatch.setattr(fs_authority_module.os, "open", capture_open)
    return captured


def test_first_audit_directory_fsync_failure_remains_recoverable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ai_qa_automation.fs_authority as fs_authority_module

    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    captured = _capture_audit_descriptor(monkeypatch)
    real_fsync = fs_authority_module.os.fsync
    audit_file_synced = False

    def fail_directory_fsync(fd: int) -> None:
        nonlocal audit_file_synced
        if fd == captured["fd"]:
            audit_file_synced = True
            real_fsync(fd)
            return
        if audit_file_synced:
            raise OSError(5, "simulated directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(fs_authority_module.os, "fsync", fail_directory_fsync)
    with pytest.raises(OSError, match="simulated directory fsync failure"):
        store.add(_item("run", "first"))

    assert store.all() == []
    restored = EvidenceStore(tmp_path, "run", regulated_mode=True)
    assert restored.all() == []


def test_descriptor_close_failure_restore_still_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ai_qa_automation.fs_authority as fs_authority_module

    store = EvidenceStore(tmp_path, "run", regulated_mode=True)
    captured = _capture_audit_descriptor(monkeypatch)
    real_close = fs_authority_module.os.close
    injected = False

    def fail_audit_close(fd: int) -> None:
        nonlocal injected
        if fd == captured["fd"] and not injected:
            injected = True
            captured["fd"] = None
            real_close(fd)
            raise OSError(5, "simulated audit descriptor close failure")
        real_close(fd)

    monkeypatch.setattr(fs_authority_module.os, "close", fail_audit_close)
    with pytest.raises(OSError, match="descriptor close could not be proven"):
        store.add(_item("run", "first"))

    assert store.all() == []
    assert store.verify_audit_chain() is True
    with pytest.raises(ValueError, match="registry does not match audit log"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)
