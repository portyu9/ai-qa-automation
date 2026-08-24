from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.models import AgentRunState
from ai_qa_automation.runtime.lineage import build_run_lineage
from ai_qa_automation.state import StateStore


def _prepare_run(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    workspace = tmp_path / "sut"
    workspace.mkdir()
    StateStore(run_dir / "state.json").save(
        AgentRunState(
            run_id="run-1",
            objective="Build strict lineage",
            workspace=str(workspace),
        )
    )
    return run_dir


def _valid_evidence(*, run_id: str = "run-1", evidence_id: str = "ev-1") -> dict[str, object]:
    return {
        "id": evidence_id,
        "run_id": run_id,
        "kind": "source_observation",
        "nature": "OBSERVED_FACT",
        "source": "unit-test",
        "summary": "Observed subject",
        "reliability": "HIGH",
        "sanitization_status": "SANITIZED",
    }


def _valid_artifact(*, artifact_id: str = "art-1", path: str = "evidence/item.json") -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "type": "json",
        "path": path,
        "originating_tool": "unit-test",
        "content_hash": "sha256:" + ("a" * 64),
        "sanitization_status": "SANITIZED",
        "retention_classification": "standard",
    }


def _write_manifest(
    run_dir: Path,
    *,
    run_id: str = "run-1",
    evidence: list[dict[str, object]] | None = None,
    artifacts: list[dict[str, object]] | None = None,
) -> None:
    (run_dir / "evidence-manifest.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "regulated_mode": False,
                "evidence": evidence or [],
                "artifacts": artifacts or [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_lineage_rejects_coercive_canonical_state_revision(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    state = AgentRunState(
        run_id="run-1",
        objective="Build strict lineage",
        workspace=str(tmp_path / "sut"),
    )
    payload = state.model_dump(mode="json")
    payload["change_revision"] = "0"
    (run_dir / "state.json").write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="change_revision"):
        build_run_lineage(run_dir)


def test_lineage_rejects_manifest_bound_to_another_run(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path)
    _write_manifest(run_dir, run_id="run-2")

    with pytest.raises(ValueError, match="manifest run_id does not match canonical state"):
        build_run_lineage(run_dir)


def test_lineage_rejects_evidence_bound_to_another_run(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path)
    _write_manifest(run_dir, evidence=[_valid_evidence(run_id="run-2")])

    with pytest.raises(ValueError, match="contains evidence from another run"):
        build_run_lineage(run_dir)


def test_lineage_rejects_malformed_evidence_schema(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path)
    evidence = _valid_evidence()
    evidence["kind"] = "invented-evidence-kind"
    _write_manifest(run_dir, evidence=[evidence])

    with pytest.raises(ValueError, match="record schema is invalid"):
        build_run_lineage(run_dir)


def test_lineage_rejects_duplicate_evidence_ids(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path)
    _write_manifest(
        run_dir,
        evidence=[
            _valid_evidence(evidence_id="ev-duplicate"),
            _valid_evidence(evidence_id="ev-duplicate"),
        ],
    )

    with pytest.raises(ValueError, match="duplicate evidence ids"):
        build_run_lineage(run_dir)


def test_lineage_rejects_duplicate_artifact_paths(tmp_path: Path) -> None:
    run_dir = _prepare_run(tmp_path)
    _write_manifest(
        run_dir,
        artifacts=[
            _valid_artifact(artifact_id="art-1", path="evidence/shared.json"),
            _valid_artifact(artifact_id="art-2", path="evidence/shared.json"),
        ],
    )

    with pytest.raises(ValueError, match="duplicate artifact paths"):
        build_run_lineage(run_dir)
