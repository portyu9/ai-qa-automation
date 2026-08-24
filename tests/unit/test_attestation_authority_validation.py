from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.attestation import build_run_attestation
from ai_qa_automation.runtime.journal import RunJournal


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def _complete_fixture(tmp_path: Path, runtime_payload: dict[str, object]) -> Path:
    run_dir = tmp_path / "run-1"
    state = AgentRunState(
        run_id="run-1",
        objective="Attest persisted authority",
        workspace=str(tmp_path / "sut"),
    )
    _write_json(run_dir / "state.json", state.model_dump(mode="json"))
    _write_json(run_dir / "evidence-manifest.json", {"evidence": [], "artifacts": []})
    _write_json(run_dir / "runtime.json", runtime_payload)
    RunJournal(run_dir / "journal.jsonl").append("run_started", run_id="run-1")
    return run_dir


@pytest.mark.parametrize("pending_mutation", [False, 0, "", [], {}])
def test_attestation_never_certifies_coercive_or_empty_pending_mutation_authority(
    tmp_path: Path,
    pending_mutation: object,
) -> None:
    run_dir = _complete_fixture(
        tmp_path,
        {"workspace_fingerprint": "fp", "pending_mutation": pending_mutation},
    )

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["subjects_complete"] is True
    assert attestation["integrity"]["journal"]["valid"] is True
    assert attestation["integrity"]["artifacts"]["valid"] is True
    assert attestation["integrity"]["integrity_verified"] is False
    assert attestation["interpretation"] == (
        "One or more persisted run-integrity checks are incomplete or failed."
    )


def test_attestation_never_certifies_missing_pending_mutation_authority(tmp_path: Path) -> None:
    run_dir = _complete_fixture(tmp_path, {"workspace_fingerprint": "fp"})

    attestation = build_run_attestation(run_dir)

    assert attestation["integrity"]["subjects_complete"] is True
    assert attestation["integrity"]["integrity_verified"] is False


def test_attestation_rejects_coercive_canonical_state_revision(tmp_path: Path) -> None:
    run_dir = _complete_fixture(
        tmp_path,
        {"workspace_fingerprint": "fp", "pending_mutation": None},
    )
    state_path = run_dir / "state.json"
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    payload["change_revision"] = "0"
    _write_json(state_path, payload)

    with pytest.raises(ValueError, match="change_revision"):
        build_run_attestation(run_dir)
