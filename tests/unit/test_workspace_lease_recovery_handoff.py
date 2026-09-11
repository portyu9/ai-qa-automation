from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import ai_qa_automation.agent as agent_module
from ai_qa_automation.agent import run_agent
from ai_qa_automation.config import Settings
from ai_qa_automation.models import TerminalStatus
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.state import StateStore


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


def _patch_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider_must_not_run: bool = False,
) -> None:
    class AcceptOptions:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

    class ForbiddenClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise AssertionError(
                "provider client construction is owned by the patched session runner"
            )

    async def session_runner(**_kwargs: object) -> None:
        if provider_must_not_run:
            raise AssertionError("provider execution must not start before lease publication")
        raise RuntimeError("deterministic provider failure after lease publication")

    monkeypatch.setattr("claude_agent_sdk.ClaudeAgentOptions", AcceptOptions)
    monkeypatch.setattr("claude_agent_sdk.ClaudeSDKClient", ForbiddenClient)
    monkeypatch.setattr(agent_module, "execute_sdk_sessions", session_runner)
    monkeypatch.setattr(
        agent_module,
        "bootstrap_runtime_context",
        lambda **_kwargs: "bounded bootstrap context",
    )
    monkeypatch.setattr(agent_module, "build_internal_mcp_server", lambda _services: (object(), []))
    monkeypatch.setattr(agent_module, "build_external_mcp", lambda _settings, _policy: ({}, {}))
    monkeypatch.setattr(agent_module, "build_permission_handler", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_module, "build_hooks", lambda *args, **kwargs: {})


def _metadata(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _persisted_state(artifacts: Path) -> tuple[Path, object]:
    state_paths = list(artifacts.glob("*/state.json"))
    assert len(state_paths) == 1
    state_path = state_paths[0]
    return state_path.parent, StateStore(state_path).load()


def test_deferred_acquire_preserves_predecessor_across_intermediate_crash(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    first = WorkspaceLease(artifact_root, workspace, "run-a").acquire()
    first_lease_id = first.lease_id
    lease_path = first.path
    first.release()
    predecessor_bytes = lease_path.read_bytes()

    intermediate = WorkspaceLease(artifact_root, workspace, "run-b").acquire(publish=False)
    try:
        assert intermediate.previous_metadata is not None
        assert intermediate.previous_metadata["run_id"] == "run-a"
        assert intermediate.previous_metadata["lease_id"] == first_lease_id
        assert lease_path.read_bytes() == predecessor_bytes
    finally:
        intermediate.release()

    assert lease_path.read_bytes() == predecessor_bytes
    successor = WorkspaceLease(artifact_root, workspace, "run-c").acquire(publish=False)
    try:
        assert successor.previous_metadata is not None
        assert successor.previous_metadata["run_id"] == "run-a"
        assert successor.previous_metadata["lease_id"] == first_lease_id
    finally:
        successor.release()


def test_deferred_publication_replaces_predecessor_only_after_handoff(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    first = WorkspaceLease(artifact_root, workspace, "run-a").acquire()
    lease_path = first.path
    first.release()

    second = WorkspaceLease(artifact_root, workspace, "run-b").acquire(publish=False)
    try:
        assert _metadata(lease_path)["run_id"] == "run-a"
        second.publish_current_owner()
        published = _metadata(lease_path)
        assert published["run_id"] == "run-b"
        assert published["lease_id"] == second.lease_id
        assert isinstance(published["acquired_at"], str)
    finally:
        second.release()

    successor = WorkspaceLease(artifact_root, workspace, "run-c").acquire(publish=False)
    try:
        assert successor.previous_metadata is not None
        assert successor.previous_metadata["run_id"] == "run-b"
    finally:
        successor.release()


def test_workspace_lease_rejects_double_acquire_while_authority_is_live(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    lease = WorkspaceLease(artifact_root, workspace, "run-a").acquire(publish=False)
    try:
        with pytest.raises(OSError, match="already acquired"):
            lease.acquire(publish=False)
    finally:
        lease.release()

    successor = WorkspaceLease(artifact_root, workspace, "run-b").acquire(publish=False)
    successor.release()


def test_torn_publication_metadata_fails_closed_until_exact_predecessor_is_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "sut"
    workspace.mkdir()

    predecessor = WorkspaceLease(artifact_root, workspace, "run-a").acquire()
    lease_path = predecessor.path
    predecessor_bytes = lease_path.read_bytes()
    predecessor.release()

    successor = WorkspaceLease(artifact_root, workspace, "run-b").acquire(publish=False)
    torn_bytes = b'{"run_id":"run-b"'

    def tear_publication(self: WorkspaceLease, stream: object, directory_fd: int | None) -> None:
        del self, directory_fd
        stream.seek(0)  # type: ignore[attr-defined]
        stream.truncate(0)  # type: ignore[attr-defined]
        stream.write(torn_bytes)  # type: ignore[attr-defined]
        stream.flush()  # type: ignore[attr-defined]
        os.fsync(stream.fileno())  # type: ignore[attr-defined]
        raise OSError("simulated torn lease publication")

    monkeypatch.setattr(WorkspaceLease, "_persist_current_owner", tear_publication)
    try:
        with pytest.raises(OSError, match="simulated torn lease publication"):
            successor.publish_current_owner()
    finally:
        successor.release()

    assert lease_path.read_bytes() == torn_bytes
    with pytest.raises(OSError, match="metadata is corrupt; manual review is required"):
        WorkspaceLease(artifact_root, workspace, "run-c").acquire(publish=False)

    lease_path.write_bytes(predecessor_bytes)
    repaired = WorkspaceLease(artifact_root, workspace, "run-d").acquire(publish=False)
    try:
        assert repaired.previous_metadata is not None
        assert repaired.previous_metadata["run_id"] == "run-a"
    finally:
        repaired.release()


@pytest.mark.asyncio
async def test_run_agent_publishes_current_owner_only_after_stale_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    predecessor = WorkspaceLease(artifacts, workspace, "run-prior").acquire()
    lease_path = predecessor.path
    predecessor_lease_id = predecessor.lease_id
    predecessor.release()
    _patch_runtime(monkeypatch)
    recovery_observed = False

    def observe_recovery(**kwargs: object) -> dict[str, str]:
        nonlocal recovery_observed
        recovery_observed = True
        previous = kwargs["previous_lease"]
        recovery_lease = kwargs["recovery_lease"]
        assert isinstance(previous, dict)
        assert isinstance(recovery_lease, WorkspaceLease)
        assert recovery_lease.previous_metadata == previous
        assert previous["run_id"] == "run-prior"
        assert previous["lease_id"] == predecessor_lease_id
        with recovery_lease.stale_recovery_authority(
            artifact_root=artifacts,
            workspace=workspace,
            recovering_run_id=recovery_lease.run_id,
            previous_lease=previous,
        ):
            durable = _metadata(lease_path)
            assert durable["run_id"] == "run-prior"
            assert durable["lease_id"] == predecessor_lease_id
        return {"status": "NONE"}

    monkeypatch.setattr(agent_module, "recover_stale_mutation", observe_recovery)

    await run_agent(
        "exercise crash-safe lease handoff",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    assert recovery_observed
    run_dir, persisted = _persisted_state(artifacts)
    published = _metadata(lease_path)
    assert published["run_id"] == persisted.run_id == run_dir.name
    assert published["lease_id"] != predecessor_lease_id


@pytest.mark.asyncio
async def test_run_agent_publication_failure_is_pre_provider_infrastructure_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control, workspace, artifacts = _runtime_roots(tmp_path)
    predecessor = WorkspaceLease(artifacts, workspace, "run-prior").acquire()
    lease_path = predecessor.path
    predecessor_lease_id = predecessor.lease_id
    predecessor.release()
    predecessor_bytes = lease_path.read_bytes()
    _patch_runtime(monkeypatch, provider_must_not_run=True)

    def no_stale_mutation(**kwargs: object) -> dict[str, str]:
        previous = kwargs["previous_lease"]
        recovery_lease = kwargs["recovery_lease"]
        assert isinstance(previous, dict)
        assert isinstance(recovery_lease, WorkspaceLease)
        assert recovery_lease.previous_metadata == previous
        assert previous["run_id"] == "run-prior"
        assert lease_path.read_bytes() == predecessor_bytes
        return {"status": "NONE"}

    def fail_publication(self: WorkspaceLease) -> WorkspaceLease:
        assert lease_path.read_bytes() == predecessor_bytes
        raise OSError("durable lease publication unavailable")

    monkeypatch.setattr(agent_module, "recover_stale_mutation", no_stale_mutation)
    monkeypatch.setattr(WorkspaceLease, "publish_current_owner", fail_publication)

    result = await run_agent(
        "exercise lease publication failure",
        workspace,
        Settings(control_root=control, artifact_root=artifacts),
    )

    report = result["report"]
    assert report["terminal_status"] == TerminalStatus.INFRASTRUCTURE_FAILURE.value
    assert "workspace lease ownership could not be published safely" in report["summary"].lower()
    assert lease_path.read_bytes() == predecessor_bytes
    assert _metadata(lease_path)["lease_id"] == predecessor_lease_id

    run_dir, persisted = _persisted_state(artifacts)
    assert persisted.terminal_status is TerminalStatus.INFRASTRUCTURE_FAILURE
    records = [json.loads(line) for line in (run_dir / "journal.jsonl").read_text().splitlines()]
    events = [record["event"] for record in records]
    assert "workspace_lease_publish_failed" in events
    assert "workspace_lease_acquired" not in events
