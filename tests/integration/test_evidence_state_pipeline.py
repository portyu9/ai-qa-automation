from pathlib import Path

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, EvidenceItem, EvidenceKind, TerminalStatus
from ai_qa_automation.reporting import build_final_report
from ai_qa_automation.state import StateStore


def test_evidence_and_state_persist_outside_conversation(tmp_path: Path) -> None:
    state = AgentRunState(
        objective="investigate",
        workspace=str(tmp_path),
        terminal_status=TerminalStatus.NOT_VERIFIED,
    )
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)
    item = evidence.add(
        EvidenceItem(
            run_id=state.run_id,
            kind=EvidenceKind.EXIT_CODE,
            source="pytest",
            summary="exit 1",
            structured_data={"exit_code": 1},
        )
    )
    state.evidence_ids.append(item.id)
    store = StateStore(tmp_path / "state.json")
    store.save(state)
    loaded = store.load()
    report = build_final_report(loaded)
    assert item.id in report.evidence_ids
    assert report.terminal_status is TerminalStatus.NOT_VERIFIED
    assert (tmp_path / "artifacts" / state.run_id / "evidence-manifest.json").is_file()


def test_artifact_path_escape_is_rejected(tmp_path: Path) -> None:
    evidence = EvidenceStore(tmp_path / "artifacts", "run")
    try:
        evidence.register_artifact(
            relative_path="../../escape.txt", content=b"bad", originating_tool="test"
        )
    except ValueError:
        pass
    else:
        raise AssertionError("path escape must be rejected")


def test_artifact_manifest_records_hash_origin_and_raw_sanitization(tmp_path: Path) -> None:
    evidence = EvidenceStore(tmp_path / "artifacts", "run-artifact")
    _, digest = evidence.register_artifact(
        relative_path="browser/screenshot.png",
        content=b"image-bytes",
        originating_tool="browser_probe",
    )
    manifest = __import__("json").loads(
        (tmp_path / "artifacts" / "run-artifact" / "evidence-manifest.json").read_text()
    )
    assert len(manifest["artifacts"]) == 1
    artifact = manifest["artifacts"][0]
    assert artifact["originating_tool"] == "browser_probe"
    assert artifact["content_hash"] == digest
    assert artifact["sanitization_status"] == "RAW"


def test_regulated_mode_emits_hash_chained_audit_log(tmp_path: Path) -> None:
    import json

    evidence = EvidenceStore(tmp_path / "artifacts", "regulated-run", regulated_mode=True)
    item = evidence.add(
        EvidenceItem(
            run_id="regulated-run",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="controlled observation",
        )
    )
    evidence.register_artifact(
        relative_path="evidence/result.txt",
        content=b"sanitized-result",
        originating_tool="test",
    )

    run_root = tmp_path / "artifacts" / "regulated-run"
    records = [json.loads(line) for line in (run_root / "audit-log.jsonl").read_text().splitlines()]
    assert len(records) == 2
    assert records[0]["previous_hash"] == "GENESIS"
    assert records[1]["previous_hash"] == records[0]["event_hash"]
    assert records[0]["payload"]["evidence_id"] == item.id

    manifest = json.loads((run_root / "evidence-manifest.json").read_text())
    assert manifest["regulated_mode"] is True
    assert manifest["audit_log"]["events"] == 2
    assert manifest["audit_log"]["last_event_hash"] == records[-1]["event_hash"]
    assert manifest["artifacts"][0]["retention_classification"] == "regulated"


def test_regulated_mode_detects_tampered_audit_log(tmp_path: Path) -> None:
    import json

    root = tmp_path / "artifacts"
    evidence = EvidenceStore(root, "tamper-run", regulated_mode=True)
    evidence.add(
        EvidenceItem(
            run_id="tamper-run",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="before tamper",
        )
    )
    path = root / "tamper-run" / "audit-log.jsonl"
    record = json.loads(path.read_text().splitlines()[0])
    record["payload"]["kind"] = "tampered"
    path.write_text(json.dumps(record) + "\n")

    try:
        EvidenceStore(root, "tamper-run", regulated_mode=True)
    except ValueError as exc:
        assert "integrity" in str(exc)
    else:
        raise AssertionError("tampered regulated audit chain must be rejected")


def test_evidence_store_reopen_preserves_manifest_items(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    first = EvidenceStore(root, "reopen")
    item = first.add(
        EvidenceItem(
            run_id="reopen",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="preserved",
        )
    )
    first.register_artifact(
        relative_path="result.txt",
        content=b"result",
        originating_tool="test",
    )

    reopened = EvidenceStore(root, "reopen")
    assert reopened.get(item.id).summary == "preserved"
    reopened.add(
        EvidenceItem(
            run_id="reopen",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="second",
        )
    )
    import json

    manifest = json.loads((root / "reopen" / "evidence-manifest.json").read_text())
    assert len(manifest["evidence"]) == 2
    assert len(manifest["artifacts"]) == 1


def test_regulated_mode_reopen_detects_artifact_tampering(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "artifact-tamper", regulated_mode=True)
    store.register_artifact(
        relative_path="result.txt",
        content=b"original",
        originating_tool="test",
    )
    (root / "artifact-tamper" / "result.txt").write_bytes(b"tampered")

    try:
        EvidenceStore(root, "artifact-tamper", regulated_mode=True)
    except ValueError as exc:
        assert "artifact integrity" in str(exc)
    else:
        raise AssertionError("regulated artifact tamper must be detected on reopen")


def test_regulated_mode_detects_manifest_evidence_tampering(tmp_path: Path) -> None:
    import json

    root = tmp_path / "artifacts"
    store = EvidenceStore(root, "manifest-tamper", regulated_mode=True)
    store.add(
        EvidenceItem(
            run_id="manifest-tamper",
            kind=EvidenceKind.SOURCE_OBSERVATION,
            source="test",
            summary="original",
        )
    )
    manifest_path = root / "manifest-tamper" / "evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["evidence"][0]["summary"] = "tampered"
    manifest_path.write_text(json.dumps(manifest))

    try:
        EvidenceStore(root, "manifest-tamper", regulated_mode=True)
    except ValueError as exc:
        assert "evidence integrity" in str(exc)
    else:
        raise AssertionError("regulated manifest tamper must be detected")


def test_evidence_ids_and_artifact_paths_are_immutable(tmp_path: Path) -> None:
    from ai_qa_automation.models import EvidenceItem, EvidenceKind

    store = EvidenceStore(tmp_path / "artifacts", "immutable")
    item = EvidenceItem(
        id="ev-fixed",
        run_id="immutable",
        kind=EvidenceKind.SOURCE_OBSERVATION,
        source="test",
        summary="first",
    )
    store.add(item)
    try:
        store.add(item.model_copy(update={"summary": "mutated"}))
    except ValueError:
        pass
    else:
        raise AssertionError("evidence ids must be append-only")

    store.register_artifact(
        relative_path="browser/fixed.png",
        content=b"first",
        originating_tool="test",
    )
    try:
        store.register_artifact(
            relative_path="browser/fixed.png",
            content=b"second",
            originating_tool="test",
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("artifact paths must be immutable")
