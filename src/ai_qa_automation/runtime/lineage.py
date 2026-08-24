from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..io_safety import open_regular_binary, parse_json_object_strict, read_json_object_bounded
from ..state import StateStore
from .journal import RunJournal

_MAX_LINEAGE_CONTROL_BYTES = 10_000_000
_MAX_LINEAGE_JOURNAL_LINE_BYTES = 1_000_000
_MAX_LINEAGE_JOURNAL_EVENTS = 10_000


@dataclass(frozen=True)
class LineageNode:
    id: str
    kind: str
    label: str
    attributes: dict[str, Any]

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class LineageEdge:
    source: str
    target: str
    relation: str

    def as_dict(self) -> dict[str, str]:
        return {"source": self.source, "target": self.target, "relation": self.relation}


@dataclass(frozen=True)
class RunLineageGraph:
    run_id: str
    nodes: tuple[LineageNode, ...]
    edges: tuple[LineageEdge, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "nodes": [item.as_dict() for item in self.nodes],
            "edges": [item.as_dict() for item in self.edges],
            "warnings": list(self.warnings),
        }

    def to_dot(self) -> str:
        lines = ["digraph ai_qa_run {", "  rankdir=LR;"]
        for node in self.nodes:
            label = _dot_escape(f"{node.kind}: {node.label}")
            lines.append(f'  "{_dot_escape(node.id)}" [label="{label}"];')
        for edge in self.edges:
            lines.append(
                f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}" '
                f'[label="{_dot_escape(edge.relation)}"];'
            )
        lines.append("}")
        return "\n".join(lines)


def build_run_lineage(run_dir: Path, *, max_journal_events: int = 500) -> RunLineageGraph:
    """Build a bounded evidence/validation/artifact/operation lineage graph from persisted records."""
    if (
        type(max_journal_events) is not int
        or not 1 <= max_journal_events <= _MAX_LINEAGE_JOURNAL_EVENTS
    ):
        raise ValueError(
            f"max_journal_events must be an integer between 1 and {_MAX_LINEAGE_JOURNAL_EVENTS}"
        )
    requested_root = run_dir.expanduser()
    if requested_root.is_symlink():
        raise ValueError("run directory is a symlink and has ambiguous ownership")
    root = requested_root.resolve()
    state_path = _owned_subject(root, "state.json")
    manifest_path = _owned_subject(root, "evidence-manifest.json")
    journal_path = _owned_subject(root, "journal.jsonl")
    if not state_path.is_file():
        raise FileNotFoundError(state_path.name)
    # Canonical state must be interpreted identically by runtime recovery,
    # attestation, and lineage. Reuse the strict StateStore authority rather than
    # accepting a weaker graph-only dictionary representation.
    state = StateStore(state_path).load().model_dump(mode="json")
    manifest = _load_object(manifest_path, required=False)
    run_id = state["run_id"]
    nodes: dict[str, LineageNode] = {}
    edges: set[tuple[str, str, str]] = set()
    warnings: list[str] = []

    run_node = f"run:{run_id}"
    nodes[run_node] = LineageNode(
        id=run_node,
        kind="run",
        label=run_id,
        attributes={
            "objective": state["objective"][:500],
            "objective_gate_id": state.get("objective_gate_id"),
            "terminal_status": state.get("terminal_status"),
            "target_git_sha": state.get("target_git_sha"),
            "configuration_version": state.get("configuration_version"),
        },
    )

    evidence_rows = manifest.get("evidence", []) if isinstance(manifest, dict) else []
    artifact_rows = manifest.get("artifacts", []) if isinstance(manifest, dict) else []
    evidence_ids: set[str] = set()
    artifact_by_path: dict[str, str] = {}

    if isinstance(evidence_rows, list):
        for raw in evidence_rows:
            if not isinstance(raw, dict):
                continue
            evidence_id = str(raw.get("id") or "")
            if not evidence_id:
                continue
            node_id = f"evidence:{evidence_id}"
            evidence_ids.add(evidence_id)
            nodes[node_id] = LineageNode(
                id=node_id,
                kind="evidence",
                label=str(raw.get("summary") or raw.get("kind") or evidence_id)[:300],
                attributes={
                    "evidence_id": evidence_id,
                    "kind": raw.get("kind"),
                    "nature": raw.get("nature"),
                    "source": raw.get("source"),
                    "source_identifier": raw.get("source_identifier"),
                    "content_hash": raw.get("content_hash"),
                    "artifact_reference": raw.get("artifact_reference"),
                    "reliability": raw.get("reliability"),
                },
            )
            edges.add((run_node, node_id, "OBSERVED"))

    if isinstance(artifact_rows, list):
        for raw in artifact_rows:
            if not isinstance(raw, dict):
                continue
            artifact_id = str(raw.get("artifact_id") or "")
            if not artifact_id:
                continue
            node_id = f"artifact:{artifact_id}"
            path = str(raw.get("path") or "")
            if path:
                artifact_by_path[path] = node_id
            nodes[node_id] = LineageNode(
                id=node_id,
                kind="artifact",
                label=path or artifact_id,
                attributes={
                    "artifact_id": artifact_id,
                    "path": path,
                    "type": raw.get("type"),
                    "content_hash": raw.get("content_hash"),
                    "originating_tool": raw.get("originating_tool"),
                    "sanitization_status": raw.get("sanitization_status"),
                    "retention_classification": raw.get("retention_classification"),
                },
            )
            edges.add((run_node, node_id, "PRODUCED_ARTIFACT"))

    if isinstance(evidence_rows, list):
        for raw in evidence_rows:
            if not isinstance(raw, dict):
                continue
            evidence_id = str(raw.get("id") or "")
            if not evidence_id:
                continue
            node_id = f"evidence:{evidence_id}"
            source_identifier = str(raw.get("source_identifier") or "")
            if source_identifier in evidence_ids:
                edges.add((f"evidence:{source_identifier}", node_id, "SOURCE_FOR"))
            related_hypothesis = str(raw.get("related_hypothesis") or "")
            if related_hypothesis:
                hypothesis_node = f"hypothesis:{related_hypothesis}"
                nodes.setdefault(
                    hypothesis_node,
                    LineageNode(hypothesis_node, "hypothesis", related_hypothesis, {}),
                )
                edges.add((node_id, hypothesis_node, "SUPPORTS_HYPOTHESIS"))
            artifact_reference = str(raw.get("artifact_reference") or "")
            artifact_node = artifact_by_path.get(artifact_reference)
            if artifact_node:
                edges.add((artifact_node, node_id, "MATERIALIZES"))

    validation_rows = state.get("validation_results", [])
    if isinstance(validation_rows, list):
        for index, raw in enumerate(validation_rows):
            if not isinstance(raw, dict):
                continue
            validation_id = str(raw.get("id") or f"validation-{index}")
            node_id = f"validation:{validation_id}"
            nodes[node_id] = LineageNode(
                id=node_id,
                kind="validation",
                label=str(raw.get("gate_id") or raw.get("name") or validation_id),
                attributes={
                    "name": raw.get("name"),
                    "gate_id": raw.get("gate_id"),
                    "revision": raw.get("revision"),
                    "status": raw.get("status"),
                    "summary": str(raw.get("summary") or "")[:500],
                },
            )
            edges.add((run_node, node_id, "VALIDATED_BY"))
            evidence_for_gate = raw.get("evidence_ids", [])
            if isinstance(evidence_for_gate, list):
                for evidence_id in evidence_for_gate:
                    eid = str(evidence_id)
                    if eid in evidence_ids:
                        edges.add((f"evidence:{eid}", node_id, "SUPPORTS_VALIDATION"))
                    else:
                        warnings.append(
                            f"validation {validation_id} references missing evidence {eid}"
                        )

    hypotheses = state.get("hypotheses", [])
    if isinstance(hypotheses, list):
        for raw in hypotheses:
            if not isinstance(raw, dict):
                continue
            hypothesis_id = str(raw.get("id") or "")
            if not hypothesis_id:
                continue
            node_id = f"hypothesis:{hypothesis_id}"
            nodes[node_id] = LineageNode(
                node_id,
                "hypothesis",
                str(raw.get("statement") or hypothesis_id)[:300],
                {"confidence": raw.get("confidence")},
            )
            edges.add((run_node, node_id, "CONSIDERED"))
            for relation, field in (
                ("SUPPORTS_HYPOTHESIS", "supporting_evidence_ids"),
                ("CONTRADICTS_HYPOTHESIS", "contradicting_evidence_ids"),
            ):
                values = raw.get(field, [])
                if isinstance(values, list):
                    for evidence_id in values:
                        eid = str(evidence_id)
                        if eid in evidence_ids:
                            edges.add((f"evidence:{eid}", node_id, relation))

    if journal_path.is_file():
        try:
            journal_status = RunJournal(journal_path, regulated_mode=False).verify()
        except (OSError, json.JSONDecodeError, RuntimeError, ValueError) as exc:
            warnings.append(f"journal could not be verified for lineage: {type(exc).__name__}")
        else:
            if not journal_status.get("valid"):
                warnings.append("journal hash chain is invalid; runtime events were not graphed")
            else:
                count = 0
                try:
                    with open_regular_binary(journal_path, label="lineage journal") as stream:
                        while True:
                            raw_line = stream.readline(_MAX_LINEAGE_JOURNAL_LINE_BYTES + 1)
                            if not raw_line:
                                break
                            if len(raw_line) > _MAX_LINEAGE_JOURNAL_LINE_BYTES:
                                warnings.append("journal event exceeds lineage line-size bound")
                                break
                            if not raw_line.strip():
                                continue
                            if count >= max_journal_events:
                                warnings.append(
                                    f"journal graph truncated at {max_journal_events} events"
                                )
                                break
                            raw = parse_json_object_strict(
                                raw_line.decode("utf-8"),
                                label=f"lineage journal record {count + 1}",
                            )
                            sequence = (
                                raw.get("seq")
                                if raw.get("seq") is not None
                                else raw.get("sequence")
                            )
                            if sequence is None:
                                sequence = count + 1
                            event_name = str(raw.get("event") or raw.get("event_type") or "event")
                            node_id = f"event:{sequence}"
                            nodes[node_id] = LineageNode(
                                node_id,
                                "runtime_event",
                                event_name,
                                {
                                    "sequence": sequence,
                                    "timestamp": raw.get("timestamp"),
                                    "record_hash": raw.get("record_hash") or raw.get("event_hash"),
                                },
                            )
                            edges.add((run_node, node_id, "RUNTIME_EVENT"))
                            count += 1
                except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    warnings.append(f"journal could not be graphed: {type(exc).__name__}")

    ordered_nodes = tuple(nodes[key] for key in sorted(nodes))
    ordered_edges = tuple(LineageEdge(*item) for item in sorted(edges))
    return RunLineageGraph(
        run_id=run_id,
        nodes=ordered_nodes,
        edges=ordered_edges,
        warnings=tuple(sorted(set(warnings))),
    )


def _owned_subject(root: Path, name: str) -> Path:
    path = root / name
    if path.is_symlink():
        raise ValueError(f"{name} is a symlink and has ambiguous ownership")
    return path


def _load_object(path: Path, *, required: bool) -> dict[str, Any]:
    if not path.is_file():
        if required:
            raise FileNotFoundError(path.name)
        return {}
    return read_json_object_bounded(
        path,
        max_bytes=_MAX_LINEAGE_CONTROL_BYTES,
        label=f"lineage control file {path.name}",
    )


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
