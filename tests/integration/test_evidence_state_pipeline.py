from pathlib import Path

from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.models import AgentRunState, EvidenceItem, EvidenceKind, TerminalStatus
from ai_qa_automation.reporting import build_final_report
from ai_qa_automation.state import StateStore


def test_evidence_and_state_persist_outside_conversation(tmp_path: Path) -> None:
    state = AgentRunState(objective="investigate", workspace=str(tmp_path), terminal_status=TerminalStatus.NOT_VERIFIED)
    evidence = EvidenceStore(tmp_path / "artifacts", state.run_id)
    item = evidence.add(EvidenceItem(run_id=state.run_id, kind=EvidenceKind.EXIT_CODE, source="pytest", summary="exit 1", structured_data={"exit_code": 1}))
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
        evidence.register_artifact(relative_path="../../escape.txt", content=b"bad", originating_tool="test")
    except ValueError:
        pass
    else:
        raise AssertionError("path escape must be rejected")
