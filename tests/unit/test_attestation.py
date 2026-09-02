from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import ai_qa_automation.runtime.attestation as attestation_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.journal import RunJournal


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def base_state(*, workspace: str) -> dict[str, object]:
    return {
        "run_id": "run-1",
        "objective": "Investigate checkout failure",
        "workspace": workspace,
        "terminal_status": "NOT_VERIFIED",
        "terminal_reason": "full regression not executed",
        "target_git_sha": "abc123",
        "agent_version": "0.1.0",
        "model_id": "claude",
        "sdk_version": "sdk",
        "policy_version": "policy",
        "tool_schema_version": "tools",
        "configuration_version": "cfg",
        "change_revision": 2,
        "validation_results": [],
    }


def write_state(run_dir: Path) -> Path:
    workspace = run_dir.parent / "sut"
    workspace.mkdir(parents=True, exist_ok=True)
    write_json(
        run_dir / "state.json",
        base_state(workspace=str(workspace.resolve())),
    )
    return workspace


def artifact_record(*, artifact_id: str, path: str, digest: str) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "type": "binary",
        "path": path,
        "originating_tool": "playwright",
        "content_hash": f"sha256:{digest}",
        "sanitization_status": "RAW",
        "retention_classification": "standard",
    }


def write_runtime_authority(
    run_dir: Path,
    *,
    workspace: str | None = None,
    pending_mutation: object | None = None,
    include_workspace: bool = True,
    include_root_identity: bool = True,
) -> None:
    journal_status = RunJournal(run_dir / "journal.jsonl").verify()
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    canonical_workspace = Path(str(state["workspace"]))
    canonical_status = canonical_workspace.stat(follow_symlinks=False)
    payload: dict[str, object] = {
        "workspace_fingerprint": "fp-1",
        "journal_event_count": journal_status["events"],
        "journal_head_hash": journal_status["head_hash"],
        "pending_mutation": pending_mutation,
    }
    if include_workspace:
        payload["workspace"] = workspace or str(canonical_workspace)
    if include_root_identity:
        payload["workspace_root_identity"] = {
            "device": canonical_status.st_dev,
            "inode": canonical_status.st_ino,
        }
    write_json(run_dir / "runtime.json", payload)


def write_complete_integrity_fixture(run_dir: Path) -> Path:
    artifact = run_dir / "browser" / "capture.bin"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"artifact-bytes")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    write_json(
        run_dir / "evidence-manifest.json",
        {
            "run_id": "run-1",
            "regulated_mode": False,
            "evidence": [
                {
                    "id": "ev-1",
                    "run_id": "run-1",
                    "kind": "dom_snapshot",
                    "nature": "OBSERVED_FACT",
                    "source": "playwright",
                    "summary": "Checkout button observed",
                    "artifact_reference": "browser/capture.bin",
                    "content_hash": f"sha256:{digest}",
                }
            ],
            "artifacts": [
                artifact_record(
                    artifact_id="art-1",
                    path="browser/capture.bin",
                    digest=digest,
                )
            ],
        },
    )
    RunJournal(run_dir / "journal.jsonl").append("run_started", run_id="run-1")
    write_runtime_authority(run_dir)
    return artifact


def test_attestation_verifies_persisted_integrity_without_claiming_signature(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("full workspace root identity attestation is unavailable")
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    artifact = write_complete_integrity_fixture(run_dir)

    attestation = build_run_attestation(run_dir)

    assert attestation["schema"] == "ai-qa-run-attestation/v1"
    assert attestation["run_id"] == "run-1"
    assert attestation["outcome"]["terminal_status"] == "NOT_VERIFIED"
    assert attestation["outcome"]["evidence_count"] == 1
    assert attestation["outcome"]["artifact_count"] == 1
    assert attestation["integrity"]["integrity_verified"] is True
    assert attestation["integrity"]["subjects_complete"] is True
    assert attestation["integrity"]["journal"]["valid"] is True
    assert attestation["integrity"]["journal_binding"] == {
        "valid": True,
        "events": 1,
        "head_hash": attestation["integrity"]["journal"]["head_hash"],
    }
    assert attestation["integrity"]["workspace"] == {"valid": True}
    assert attestation["integrity"]["manifest"] == {
        "valid": True,
        "regulated_mode": False,
        "evidence_records": 1,
        "artifact_records": 1,
    }
    assert attestation["integrity"]["artifacts"] == {
        "valid": True,
        "checked": 1,
        "total_bytes": artifact.stat().st_size,
    }
    assert attestation["signature"] == {
        "signed": False,
        "reason": "repository provides content-addressed integrity metadata but no trusted signing key",
    }
    assert str(attestation["attestation_digest"]).startswith("sha256:")
    assert "does not change" in attestation["interpretation"]


def test_pending_mutation_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    artifact = write_complete_integrity_fixture(run_dir)
    assert artifact.is_file()
    write_runtime_authority(
        run_dir,
        pending_mutation={"path": "tests/test_x.py"},
    )

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["pending_mutation"] is True
    assert attestation["integrity"]["integrity_verified"] is False
    assert (
        attestation["interpretation"]
        == "One or more persisted run-integrity checks are incomplete or failed."
    )


def test_tampered_journal_is_reported_not_fabricated_as_valid(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    journal_path = run_dir / "journal.jsonl"

    record = json.loads(journal_path.read_text(encoding="utf-8"))
    record["event"] = "tampered"
    journal_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["journal"]["valid"] is False
    assert attestation["integrity"]["journal_binding"]["valid"] is False


def test_hash_valid_journal_growth_without_runtime_sync_prevents_integrity_verified(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    RunJournal(run_dir / "journal.jsonl").append("unexpected_valid_event")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["journal"]["valid"] is True
    assert attestation["integrity"]["journal"]["events"] == 2
    assert attestation["integrity"]["journal_binding"]["valid"] is False
    assert "does not match" in attestation["integrity"]["journal_binding"]["reason"]
    assert attestation["integrity"]["integrity_verified"] is False


def test_missing_runtime_journal_authority_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    runtime_path = run_dir / "runtime.json"
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime.pop("journal_head_hash")
    write_json(runtime_path, runtime)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["journal"]["valid"] is True
    assert attestation["integrity"]["journal_binding"] == {
        "valid": False,
        "reason": "runtime journal_head_hash authority is missing",
    }
    assert attestation["integrity"]["integrity_verified"] is False


def test_tampered_registered_artifact_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    artifact = write_complete_integrity_fixture(run_dir)
    artifact.write_bytes(b"tampered")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["artifacts"]["valid"] is False
    assert "hash mismatch" in attestation["integrity"]["artifacts"]["reason"]


def test_cross_run_evidence_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    manifest_path = run_dir / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["evidence"][0]["run_id"] = "run-2"
    write_json(manifest_path, manifest)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["manifest"] == {
        "valid": False,
        "reason": "evidence manifest contains evidence from another run",
    }
    assert attestation["outcome"]["evidence_count"] == 0
    assert attestation["outcome"]["artifact_count"] == 0


def test_mismatched_runtime_workspace_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    write_runtime_authority(run_dir, workspace=str(tmp_path / "other-sut"))

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["workspace"] == {
        "valid": False,
        "reason": "runtime workspace identity mismatch",
    }


def test_missing_runtime_workspace_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    write_runtime_authority(run_dir, include_workspace=False)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["workspace"] == {
        "valid": False,
        "reason": "runtime workspace identity is missing or invalid",
    }


def test_missing_runtime_workspace_root_identity_prevents_integrity_verified(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    write_complete_integrity_fixture(run_dir)
    write_runtime_authority(run_dir, include_root_identity=False)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["workspace"] == {
        "valid": False,
        "reason": "runtime workspace root identity authority is missing",
    }


def test_replaced_workspace_root_cannot_receive_green_attestation(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("workspace root identity pinning is unavailable")
    run_dir = tmp_path / "run-1"
    workspace = write_state(run_dir)
    write_complete_integrity_fixture(run_dir)

    original = tmp_path / "sut-original"
    workspace.rename(original)
    workspace.mkdir()

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["workspace"] == {
        "valid": False,
        "reason": "runtime workspace root identity mismatch",
    }


def test_attestation_fails_closed_when_registered_artifacts_exceed_cumulative_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    RunJournal(run_dir / "journal.jsonl").append("run_started", run_id="run-1")
    write_runtime_authority(run_dir)
    artifacts: list[dict[str, object]] = []
    for index, payload in enumerate((b"123456", b"abcdef"), 1):
        path = run_dir / "browser" / f"capture-{index}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        artifacts.append(
            artifact_record(
                artifact_id=f"art-{index}",
                path=path.relative_to(run_dir).as_posix(),
                digest=hashlib.sha256(payload).hexdigest(),
            )
        )
    write_json(
        run_dir / "evidence-manifest.json",
        {
            "run_id": "run-1",
            "regulated_mode": False,
            "evidence": [],
            "artifacts": artifacts,
        },
    )
    monkeypatch.setattr(attestation_module, "_MAX_TOTAL_ARTIFACT_BYTES", 10)

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["manifest"]["valid"] is True
    assert attestation["integrity"]["artifacts"]["valid"] is False
    assert "cumulative" in attestation["integrity"]["artifacts"]["reason"]


def test_missing_core_subjects_prevent_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_state(run_dir)
    RunJournal(run_dir / "journal.jsonl").append("run_started")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["subjects_complete"] is False
    assert attestation["integrity"]["manifest"]["valid"] is False
    assert attestation["integrity"]["integrity_verified"] is False


def test_attestation_rejects_symlinked_subject(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    outside = tmp_path / "outside-state.json"
    write_json(
        outside,
        base_state(workspace=str((tmp_path / "sut").resolve())),
    )
    try:
        (run_dir / "state.json").symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match=r"state\.json.*symlink"):
        build_run_attestation(run_dir)


def test_attestation_requires_state(tmp_path: Path) -> None:
    run_dir = tmp_path / "missing-state"
    run_dir.mkdir()

    with pytest.raises(FileNotFoundError, match=r"state\.json"):
        build_run_attestation(run_dir)
