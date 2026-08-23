from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.lineage import build_run_lineage


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def test_lineage_connects_evidence_artifacts_hypotheses_and_validation(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-123"
    write_json(
        run_dir / "state.json",
        {
            "run_id": "run-123",
            "objective": "Investigate checkout failure",
            "terminal_status": "NOT_VERIFIED",
            "target_git_sha": "abc123",
            "configuration_version": "cfg-1",
            "validation_results": [
                {
                    "id": "val-1",
                    "name": "targeted pytest",
                    "gate_id": "pytest-targeted",
                    "revision": 1,
                    "status": "PASS",
                    "summary": "targeted test passed",
                    "evidence_ids": ["ev-1", "ev-missing"],
                }
            ],
            "hypotheses": [
                {
                    "id": "hyp-1",
                    "statement": "locator changed",
                    "confidence": 0.7,
                    "supporting_evidence_ids": ["ev-1"],
                    "contradicting_evidence_ids": [],
                }
            ],
        },
    )
    write_json(
        run_dir / "evidence-manifest.json",
        {
            "evidence": [
                {
                    "id": "ev-1",
                    "kind": "DOM",
                    "nature": "OBSERVED_FACT",
                    "source": "playwright",
                    "source_identifier": "page",
                    "summary": "Checkout button observed",
                    "content_hash": "sha256:123",
                    "artifact_reference": "artifacts/dom.json",
                    "reliability": "HIGH",
                    "related_hypothesis": "hyp-1",
                }
            ],
            "artifacts": [
                {
                    "artifact_id": "art-1",
                    "type": "DOM",
                    "path": "artifacts/dom.json",
                    "content_hash": "sha256:456",
                    "originating_tool": "playwright",
                    "sanitization_status": "SANITIZED",
                    "retention_classification": "standard",
                }
            ],
        },
    )
    RunJournal(run_dir / "journal.jsonl").append("run_started")

    graph = build_run_lineage(run_dir)
    node_ids = {node.id for node in graph.nodes}
    edges = {(edge.source, edge.target, edge.relation) for edge in graph.edges}

    assert graph.run_id == "run-123"
    assert {
        "run:run-123",
        "evidence:ev-1",
        "artifact:art-1",
        "hypothesis:hyp-1",
        "validation:val-1",
        "event:1",
    } <= node_ids
    assert ("artifact:art-1", "evidence:ev-1", "MATERIALIZES") in edges
    assert ("evidence:ev-1", "hypothesis:hyp-1", "SUPPORTS_HYPOTHESIS") in edges
    assert ("evidence:ev-1", "validation:val-1", "SUPPORTS_VALIDATION") in edges
    assert graph.warnings == ("validation val-1 references missing evidence ev-missing",)

    dot = graph.to_dot()
    assert dot.startswith("digraph ai_qa_run {")
    assert '"evidence:ev-1" -> "validation:val-1"' in dot


def test_lineage_bounds_journal_graph(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    write_json(run_dir / "state.json", {"run_id": "run", "objective": "bounded"})
    journal = RunJournal(run_dir / "journal.jsonl")
    for index in range(1, 4):
        journal.append(f"event-{index}")

    graph = build_run_lineage(run_dir, max_journal_events=2)

    assert "journal graph truncated at 2 events" in graph.warnings
    assert {node.id for node in graph.nodes if node.kind == "runtime_event"} == {
        "event:1",
        "event:2",
    }


def test_lineage_does_not_graph_invalid_journal_events(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    write_json(run_dir / "state.json", {"run_id": "run", "objective": "tamper"})
    (run_dir / "journal.jsonl").write_text('{"seq": 1, "event": "forged"}\n', encoding="utf-8")

    graph = build_run_lineage(run_dir)

    assert not [node for node in graph.nodes if node.kind == "runtime_event"]
    assert any("journal" in warning for warning in graph.warnings)


def test_lineage_rejects_symlinked_control_subject(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside-state.json"
    write_json(outside, {"run_id": "outside"})
    state_path = run_dir / "state.json"
    try:
        state_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        build_run_lineage(run_dir)


@pytest.mark.parametrize("bound", [0, -1, True, 1.5, 10_001])
def test_lineage_rejects_invalid_event_bound(tmp_path: Path, bound: object) -> None:
    write_json(tmp_path / "run" / "state.json", {"run_id": "run"})

    with pytest.raises(ValueError, match="max_journal_events"):
        build_run_lineage(
            tmp_path / "run",
            max_journal_events=bound,  # type: ignore[arg-type]
        )


def test_lineage_requires_persisted_state(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match=r"state\.json"):
        build_run_lineage(tmp_path / "missing")
