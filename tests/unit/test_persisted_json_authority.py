from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.io_safety import parse_json_object_strict
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.lineage import build_run_lineage
from ai_qa_automation.runtime.recovery import inspect_recovery
from ai_qa_automation.runtime.stale_recovery import recover_stale_mutation
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore


def _write_state(path: Path, *, workspace: Path) -> AgentRunState:
    state = AgentRunState(objective="persisted authority", workspace=str(workspace))
    StateStore(path).save(state)
    return state


def _write_duplicate_pending_runtime(path: Path, *, workspace: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "{"
        f'"workspace":{json.dumps(str(workspace.resolve()))},'
        '"workspace_fingerprint":"fp",'
        '"journal_event_count":0,'
        '"pending_mutation":{"relative_path":"tests/test_x.py","existed":false},'
        '"pending_mutation":null'
        "}",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "raw",
    [
        '{"outer":{"revision":1,"revision":2}}',
        '{"value":NaN}',
        '{"value":Infinity}',
        '{"value":-Infinity}',
        "[]",
    ],
)
def test_strict_json_object_parser_rejects_ambiguous_or_nonstandard_input(raw: str) -> None:
    with pytest.raises((ValueError, json.JSONDecodeError)):
        parse_json_object_strict(raw, label="authority fixture")


def test_state_store_rejects_duplicate_authority_key(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state = AgentRunState(objective="state", workspace=str(workspace))
    payload = json.dumps(state.model_dump(mode="json"), sort_keys=True)
    state_path = tmp_path / "state.json"
    state_path.write_text('{"change_revision":999,' + payload[1:], encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key: change_revision"):
        StateStore(state_path).load()


def test_state_store_rejects_string_coercion_for_revision_authority(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state = AgentRunState(objective="state", workspace=str(workspace))
    payload = state.model_dump(mode="json")
    payload["change_revision"] = "0"
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError, match="change_revision"):
        StateStore(state_path).load()


def test_stale_recovery_does_not_hide_pending_mutation_behind_duplicate_key(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    _write_duplicate_pending_runtime(
        artifact_root / "run-old" / "runtime.json", workspace=workspace
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert "duplicate JSON key: pending_mutation" in str(result["reason"])


def test_stale_recovery_rejects_coercive_existed_flag_before_touching_target(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    prior_run = artifact_root / "run-old"
    rollback = prior_run / "rollback"
    rollback.mkdir(parents=True)
    workspace = tmp_path / "sut"
    workspace.mkdir()
    target = workspace / "tests" / "test_x.py"
    target.parent.mkdir()
    target.write_text("mutated\n", encoding="utf-8")
    backup = rollback / "backup.bin"
    backup_content = b"original\n"
    backup.write_bytes(backup_content)
    journal = RunJournal(prior_run / "journal.jsonl")
    journal.append("mutation_prepared")
    (prior_run / "runtime.json").write_text(
        json.dumps(
            {
                "workspace": str(workspace.resolve()),
                "workspace_fingerprint": "fp",
                "journal_event_count": journal.event_count,
                "journal_head_hash": journal.head_hash,
                "pending_mutation": {
                    "relative_path": "tests/test_x.py",
                    "existed": "false",
                    "backup_path": str(backup),
                    "original_sha256": hashlib.sha256(backup_content).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )

    result = recover_stale_mutation(
        artifact_root=artifact_root,
        workspace=workspace,
        previous_lease={"run_id": "run-old"},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result["status"] == "BLOCKED"
    assert result["reason"] == "prior pending mutation existed flag is invalid"
    assert target.read_text(encoding="utf-8") == "mutated\n"


def test_stale_recovery_rejects_non_string_prior_lease_run_id(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()

    result = recover_stale_mutation(
        artifact_root=tmp_path / "artifacts",
        workspace=workspace,
        previous_lease={"run_id": 123},
        current_workspace_fingerprint="fp",
        recovering_run_id="run-new",
    )

    assert result == {"status": "BLOCKED", "reason": "prior lease run_id is invalid"}


def test_recovery_inspection_does_not_certify_duplicate_pending_state(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    _write_state(run_dir / "state.json", workspace=workspace)
    RunJournal(run_dir / "journal.jsonl").append("persisted")
    _write_duplicate_pending_runtime(run_dir / "runtime.json", workspace=workspace)

    result = inspect_recovery(run_dir)

    assert result["recoverable"] is False
    assert "duplicate JSON key: pending_mutation" in str(result["reason"])


def test_attestation_rejects_ambiguous_runtime_subject(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    _write_state(run_dir / "state.json", workspace=workspace)
    _write_duplicate_pending_runtime(run_dir / "runtime.json", workspace=workspace)

    with pytest.raises(ValueError, match="duplicate JSON key: pending_mutation"):
        build_run_attestation(run_dir)


def test_evidence_manifest_rejects_duplicate_regulated_mode(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "evidence-manifest.json").write_text(
        '{"run_id":"run","regulated_mode":true,"regulated_mode":false,'
        '"evidence":[],"artifacts":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON key: regulated_mode"):
        EvidenceStore(tmp_path, "run", regulated_mode=False)


def test_evidence_manifest_rejects_truthy_string_regulated_mode(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "run_id": "run",
                "regulated_mode": "false",
                "evidence": [],
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="regulated_mode must be a boolean"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)


def test_regulated_audit_rejects_hash_valid_duplicate_record(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "run_id": "run",
                "regulated_mode": True,
                "evidence": [],
                "artifacts": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    core = {
        "sequence": 1,
        "timestamp": "2026-08-24T00:00:00+00:00",
        "event_type": "last-wins-event",
        "payload": {},
        "previous_hash": "GENESIS",
    }
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_hash = EvidenceStore.hash_bytes(canonical)
    raw = (
        '{"sequence":1,"timestamp":"2026-08-24T00:00:00+00:00",'
        '"event_type":"shadowed-event","event_type":"last-wins-event",'
        f'"payload":{{}},"previous_hash":"GENESIS","event_hash":"{event_hash}"}}\n'
    )
    (run_root / "audit-log.jsonl").write_text(raw, encoding="utf-8")

    with pytest.raises(ValueError, match="audit log integrity check failed"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)


def test_regulated_audit_rejects_hash_valid_string_sequence(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    (run_root / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "run_id": "run",
                "regulated_mode": True,
                "evidence": [],
                "artifacts": [],
            }
        ),
        encoding="utf-8",
    )
    core = {
        "sequence": "1",
        "timestamp": "2026-08-24T00:00:00+00:00",
        "event_type": "coercive-sequence",
        "payload": {},
        "previous_hash": "GENESIS",
    }
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record = {**core, "event_hash": EvidenceStore.hash_bytes(canonical)}
    (run_root / "audit-log.jsonl").write_text(
        json.dumps(record, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="audit log integrity check failed"):
        EvidenceStore(tmp_path, "run", regulated_mode=True)


def test_run_journal_rejects_hash_valid_duplicate_record(tmp_path: Path) -> None:
    journal_path = tmp_path / "journal.jsonl"
    body = {
        "seq": 1,
        "timestamp": "2026-08-24T00:00:00+00:00",
        "event": "last-wins-event",
        "payload": {},
        "prev_hash": None,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    raw = (
        '{"seq":1,"timestamp":"2026-08-24T00:00:00+00:00",'
        '"event":"shadowed-event","event":"last-wins-event",'
        f'"payload":{{}},"prev_hash":null,"record_hash":"{record_hash}"}}\n'
    )
    journal_path.write_text(raw, encoding="utf-8")

    with pytest.raises(RuntimeError, match="hash-chain verification"):
        RunJournal(journal_path)


def test_workspace_lease_rejects_duplicate_identity_metadata(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    lease = WorkspaceLease(artifact_root, workspace, "run-new")
    raw = (
        "{"
        f'"workspace":{json.dumps(str(workspace.resolve()))},'
        '"run_id":"run-old","lease_id":"shadowed","lease_id":"lease-old"'
        "}"
    ).encode()

    with pytest.raises(OSError, match="corrupt or ambiguous"):
        lease._parse_previous_metadata(raw)


def test_workspace_lease_rejects_coercive_identity_types(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    workspace = tmp_path / "sut"
    workspace.mkdir()
    lease = WorkspaceLease(artifact_root, workspace, "run-new")
    raw = json.dumps(
        {
            "workspace": str(workspace.resolve()),
            "run_id": 123,
            "lease_id": 456,
        }
    ).encode()

    with pytest.raises(OSError, match="run_id must be a non-empty string"):
        lease._parse_previous_metadata(raw)


def test_lineage_rejects_duplicate_persisted_run_identity(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "state.json").write_text(
        '{"run_id":"shadowed","run_id":"run","objective":"lineage"}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON key: run_id"):
        build_run_lineage(run_dir)
