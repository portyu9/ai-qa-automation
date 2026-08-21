from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.journal import RunJournal


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def base_state() -> dict[str, object]:
    return {
        "run_id": "run-1",
        "objective": "Investigate checkout",
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
        "validation_results": [{"status": "PASS"}],
    }


def test_attestation_verifies_persisted_integrity_without_claiming_signature(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_json(run_dir / "state.json", base_state())
    write_json(
        run_dir / "evidence-manifest.json",
        {"evidence": [{"id": "ev-1"}], "artifacts": [{"artifact_id": "art-1"}]},
    )
    write_json(
        run_dir / "runtime.json",
        {"workspace_fingerprint": "fp-1", "pending_mutation": None},
    )
    journal = RunJournal(run_dir / "journal.jsonl")
    journal.append("run_started", run_id="run-1")

    attestation = build_run_attestation(run_dir)

    assert attestation["schema"] == "ai-qa-run-attestation/v1"
    assert attestation["run_id"] == "run-1"
    assert attestation["outcome"]["terminal_status"] == "NOT_VERIFIED"
    assert attestation["outcome"]["evidence_count"] == 1
    assert attestation["outcome"]["artifact_count"] == 1
    assert attestation["integrity"]["integrity_verified"] is True
    assert attestation["integrity"]["journal"]["valid"] is True
    assert attestation["signature"] == {
        "signed": False,
        "reason": "repository provides content-addressed integrity metadata but no trusted signing key",
    }
    assert str(attestation["attestation_digest"]).startswith("sha256:")
    assert "does not change the run terminal status" in attestation["interpretation"]


def test_pending_mutation_prevents_integrity_verified(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_json(run_dir / "state.json", base_state())
    write_json(
        run_dir / "runtime.json",
        {"workspace_fingerprint": "fp-1", "pending_mutation": {"path": "tests/test_x.py"}},
    )
    RunJournal(run_dir / "journal.jsonl").append("mutation_started")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["pending_mutation"] is True
    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["interpretation"] == "One or more persisted run-integrity checks are incomplete or failed."


def test_tampered_journal_is_reported_not_fabricated_as_valid(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    write_json(run_dir / "state.json", base_state())
    journal_path = run_dir / "journal.jsonl"
    RunJournal(journal_path).append("run_started")

    record = json.loads(journal_path.read_text(encoding="utf-8"))
    record["event"] = "tampered"
    journal_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["integrity"]["journal"]["valid"] is False


def test_attestation_requires_state(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="state.json"):
        build_run_attestation(tmp_path / "missing")
