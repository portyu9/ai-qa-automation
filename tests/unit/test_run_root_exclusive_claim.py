from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

import ai_qa_automation.agent as agent_module
import ai_qa_automation.models as models_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.state import StateStore

_RUN_ID = "run-aaaaaaaaaaaa"


class _FixedUUID:
    def __init__(self, value: str) -> None:
        self.hex = value


def _force_generated_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    values = iter(
        [
            _FixedUUID("a" * 32),
            _FixedUUID("b" * 32),
        ]
    )
    monkeypatch.setattr(models_module, "uuid4", lambda: next(values))


def _runtime_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    control = tmp_path / "control"
    workspace = tmp_path / "target"
    artifacts = tmp_path / "artifacts"
    (control / ".claude").mkdir(parents=True)
    workspace.mkdir()
    (control / "CLAUDE.md").write_text("trusted instructions\n", encoding="utf-8")
    (control / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    for skill in (
        "investigate-test-failure",
        "self-heal-test",
        "generate-test",
        "prioritize-regression",
        "performance-test",
    ):
        skill_file = control / ".claude" / "skills" / skill / "SKILL.md"
        skill_file.parent.mkdir(parents=True, exist_ok=True)
        skill_file.write_text(f"{skill} authority\n", encoding="utf-8")
    return control, workspace, artifacts


def _historical_state(artifacts: Path, workspace: Path) -> tuple[Path, bytes, bytes, bytes]:
    run_root = artifacts / _RUN_ID
    state_path = run_root / "state.json"
    state_store = StateStore(state_path, claim_parent_exclusively=True)
    state_store.save(
        AgentRunState(
            run_id=_RUN_ID,
            session_id="session-historical",
            objective="historical authority",
            workspace=str(workspace),
        )
    )
    journal_path = run_root / "journal.jsonl"
    runtime_path = run_root / "runtime.json"
    journal_path.write_bytes(b'historical journal bytes\n')
    runtime_path.write_bytes(b'{"historical":true}\n')
    return (
        state_path,
        state_path.read_bytes(),
        journal_path.read_bytes(),
        runtime_path.read_bytes(),
    )


def test_fresh_run_root_claim_allows_initial_and_subsequent_state_writes(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state = AgentRunState(
        run_id="run-fresh",
        session_id="session-fresh",
        objective="fresh run root claim",
        workspace=str(workspace),
    )
    store = StateStore(
        tmp_path / "artifacts" / state.run_id / "state.json",
        claim_parent_exclusively=True,
    )

    store.save(state)
    state.phase = "RUNNING"
    store.save(state)

    loaded = StateStore(store.path).load()
    assert loaded.run_id == state.run_id
    assert loaded.session_id == state.session_id
    assert loaded.phase == "RUNNING"


def test_fresh_claim_creates_shared_persistence_parent_before_run_root(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    artifacts = tmp_path / "nested" / "artifacts"
    state = AgentRunState(
        run_id="run-nested-parent",
        session_id="session-nested-parent",
        objective="separate shared persistence parent from run claim",
        workspace=str(workspace),
    )

    store = StateStore(
        artifacts / state.run_id / "state.json",
        claim_parent_exclusively=True,
    )
    store.save(state)

    assert artifacts.is_dir()
    assert store.path.parent.parent == artifacts.resolve()
    assert StateStore(store.path).load().run_id == state.run_id


def test_existing_run_root_cannot_be_adopted_by_exclusive_store(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state_path, historical_state, _journal, _runtime = _historical_state(
        tmp_path / "artifacts",
        workspace,
    )
    colliding = AgentRunState(
        run_id=_RUN_ID,
        session_id="session-collision",
        objective="must not overwrite historical authority",
        workspace=str(workspace),
    )

    reopened = StateStore(state_path, claim_parent_exclusively=True)
    with pytest.raises(FileExistsError, match="not freshly claimed"):
        reopened.save(colliding)
    assert state_path.read_bytes() == historical_state

    loaded = reopened.load()
    loaded.phase = "RECOVERED"
    with pytest.raises(FileExistsError, match="cannot be adopted"):
        reopened.save(loaded)
    assert state_path.read_bytes() == historical_state

    recovery_store = StateStore(state_path)
    recovered = recovery_store.load()
    recovered.phase = "RECOVERED"
    recovery_store.save(recovered)
    assert StateStore(state_path).load().phase == "RECOVERED"


def test_preexisting_empty_run_root_cannot_be_claimed_by_first_state_write(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    run_root = tmp_path / "artifacts" / "run-existing-empty"
    run_root.mkdir(parents=True)
    state_path = run_root / "state.json"
    store = StateStore(state_path, claim_parent_exclusively=True)
    state = AgentRunState(
        run_id=run_root.name,
        session_id="session-new",
        objective="empty root still has prior ownership",
        workspace=str(workspace),
    )

    with pytest.raises(FileExistsError, match="not freshly claimed"):
        store.save(state)
    assert not state_path.exists()


def test_first_state_write_is_create_only_after_fresh_root_claim(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state_path = tmp_path / "artifacts" / "run-first-write-race" / "state.json"
    store = StateStore(state_path, claim_parent_exclusively=True)
    unexpected = b"unexpected concurrent state\n"
    state_path.write_bytes(unexpected)
    state = AgentRunState(
        run_id="run-first-write-race",
        session_id="session-new",
        objective="create-only canonical state",
        workspace=str(workspace),
    )

    with pytest.raises(FileExistsError):
        store.save(state)
    assert state_path.read_bytes() == unexpected


def test_concurrent_same_run_root_claim_has_exactly_one_writer(tmp_path: Path) -> None:
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state_path = tmp_path / "artifacts" / "run-race" / "state.json"
    barrier = Barrier(2)

    def attempt(index: int) -> str:
        store = StateStore(state_path, claim_parent_exclusively=True)
        state = AgentRunState(
            run_id="run-race",
            session_id=f"session-{index}",
            objective=f"claim attempt {index}",
            workspace=str(workspace),
        )
        barrier.wait(timeout=5)
        try:
            store.save(state)
        except FileExistsError:
            return "blocked"
        return "saved"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(attempt, (1, 2)))

    assert outcomes == ["blocked", "saved"]
    persisted = StateStore(state_path).load()
    assert persisted.session_id in {"session-1", "session-2"}


def test_symlinked_existing_run_root_is_rejected_without_touching_target(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_text("do not touch\n", encoding="utf-8")
    run_root = artifacts / "run-symlink"
    try:
        run_root.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="state directory is a symlink"):
        StateStore(run_root / "state.json", claim_parent_exclusively=True)
    assert marker.read_text(encoding="utf-8") == "do not touch\n"
    assert not (outside / "state.json").exists()


@pytest.mark.asyncio
async def test_run_agent_collision_preserves_historical_run_and_never_starts_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    state_path, state_before, journal_before, runtime_before = _historical_state(
        artifacts,
        workspace,
    )
    _force_generated_run_id(monkeypatch)

    async def forbidden_provider(**_kwargs: object) -> None:
        raise AssertionError("provider execution must not start on run-root collision")

    monkeypatch.setattr(agent_module, "execute_sdk_sessions", forbidden_provider)

    with pytest.raises(FileExistsError, match="not freshly claimed"):
        await run_agent(
            "exercise run-root collision",
            workspace,
            Settings(control_root=control, artifact_root=artifacts),
        )

    assert state_path.read_bytes() == state_before
    assert (state_path.parent / "journal.jsonl").read_bytes() == journal_before
    assert (state_path.parent / "runtime.json").read_bytes() == runtime_before


@pytest.mark.asyncio
async def test_control_provenance_failure_collision_preserves_historical_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    state_path, state_before, journal_before, runtime_before = _historical_state(
        artifacts,
        workspace,
    )
    _force_generated_run_id(monkeypatch)

    def fail_capture(_control_root: Path) -> object:
        raise OSError("simulated control-plane observation failure")

    async def forbidden_provider(**_kwargs: object) -> None:
        raise AssertionError("provider execution must not start on provenance failure")

    monkeypatch.setattr(agent_module, "capture_control_plane_subject", fail_capture)
    monkeypatch.setattr(agent_module, "execute_sdk_sessions", forbidden_provider)

    with pytest.raises(FileExistsError, match="not freshly claimed"):
        await run_agent(
            "exercise provenance-path run-root collision",
            workspace,
            Settings(control_root=control, artifact_root=artifacts),
        )

    assert state_path.read_bytes() == state_before
    assert (state_path.parent / "journal.jsonl").read_bytes() == journal_before
    assert (state_path.parent / "runtime.json").read_bytes() == runtime_before
