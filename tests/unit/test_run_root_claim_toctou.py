from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.state as state_module
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.state import StateStore


def test_parent_path_replacement_during_run_root_claim_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not state_module.descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow authority is unavailable on this platform")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    state_path = artifacts / "run-parent-race" / "state.json"
    displaced = tmp_path / "artifacts-original"
    attacker_marker = b"attacker-owned\n"
    real_mkdir = os.mkdir
    swapped = False

    def racing_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        real_mkdir(path, mode, dir_fd=dir_fd)
        if not swapped and dir_fd is not None and os.fspath(path) == "run-parent-race":
            swapped = True
            artifacts.rename(displaced)
            real_mkdir(artifacts, 0o755)
            real_mkdir(artifacts / "run-parent-race", 0o755)
            (artifacts / "run-parent-race" / "marker.bin").write_bytes(attacker_marker)

    monkeypatch.setattr(state_module.os, "mkdir", racing_mkdir)

    with pytest.raises(ValueError, match="persistence root changed identity"):
        StateStore(state_path, claim_parent_exclusively=True)

    assert swapped is True
    assert (artifacts / "run-parent-race" / "marker.bin").read_bytes() == attacker_marker
    assert not (artifacts / "run-parent-race" / "state.json").exists()
    assert not (displaced / "run-parent-race" / "state.json").exists()


def test_fallback_exclusive_claim_refuses_existing_run_root_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(state_module, "descriptor_relative_authority_supported", lambda: False)
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state_path = tmp_path / "artifacts" / "run-fallback" / "state.json"
    historical = AgentRunState(
        run_id="run-fallback",
        session_id="session-historical",
        objective="fallback historical authority",
        workspace=str(workspace),
    )
    owner = StateStore(state_path, claim_parent_exclusively=True)
    owner.save(historical)
    historical_bytes = state_path.read_bytes()

    colliding = StateStore(state_path, claim_parent_exclusively=True)
    with pytest.raises(FileExistsError, match="not freshly claimed"):
        colliding.save(
            historical.model_copy(
                update={
                    "session_id": "session-collision",
                    "objective": "must not overwrite fallback history",
                }
            )
        )

    assert state_path.read_bytes() == historical_bytes


def test_fallback_interrupted_initial_write_never_publishes_partial_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(state_module, "descriptor_relative_authority_supported", lambda: False)
    workspace = tmp_path / "sut"
    workspace.mkdir()
    state_path = tmp_path / "artifacts" / "run-fallback-interrupted" / "state.json"
    store = StateStore(state_path, claim_parent_exclusively=True)
    state = AgentRunState(
        run_id="run-fallback-interrupted",
        session_id="session-interrupted",
        objective="fallback publication must remain atomic",
        workspace=str(workspace),
    )
    real_write = os.write
    write_calls = 0

    def interrupted_write(fd: int, data: bytes | bytearray | memoryview) -> int:
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            partial = bytes(data[: max(1, len(data) // 2)])
            return real_write(fd, partial)
        raise OSError("simulated interrupted fallback state write")

    monkeypatch.setattr(state_module.os, "write", interrupted_write)

    with pytest.raises(OSError, match="simulated interrupted fallback state write"):
        store.save(state)

    assert write_calls == 2
    assert not state_path.exists()
    assert list(state_path.parent.glob(f".{state_path.name}.*.tmp")) == []
