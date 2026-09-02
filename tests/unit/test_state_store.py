from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import ai_qa_automation.fs_authority as fs_authority
from ai_qa_automation.models import (
    AgentRunState,
    MCPStatus,
    TerminalStatus,
    ValidationResult,
    ValidationStatus,
)
from ai_qa_automation.state import StateStore


def test_state_round_trip_preserves_decision_and_validation_lineage(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "run" / "state.json"
    store = StateStore(path)
    state = AgentRunState(
        run_id="run-roundtrip",
        objective="verify checkout",
        workspace=str(tmp_path / "sut"),
        change_revision=2,
        terminal_status=TerminalStatus.NOT_VERIFIED,
        mcp_status={"github": MCPStatus.RATE_LIMITED},
        validation_results=[
            ValidationResult(
                name="pytest",
                gate_id="pytest:target",
                revision=2,
                status=ValidationStatus.PASS,
                summary="targeted pass",
                details={"scope": "targeted"},
            )
        ],
    )

    store.save(state)
    loaded = store.load()

    assert loaded == state
    assert loaded.change_revision == 2
    assert loaded.validation_results[0].revision == 2
    assert loaded.mcp_status["github"] is MCPStatus.RATE_LIMITED
    assert path.is_file()


def test_state_store_creates_parent_directories(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "c" / "state.json"
    store = StateStore(path)
    store.save(AgentRunState(objective="x", workspace=str(tmp_path)))
    assert path.is_file()


def test_corrupt_json_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        StateStore(path).load()


def test_unknown_persisted_fields_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = AgentRunState(objective="x", workspace=str(tmp_path))
    payload = state.model_dump(mode="json")
    payload["untrusted_new_authority"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationError):
        StateStore(path).load()


def test_state_store_rejects_symlinked_state_file(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    state_path = tmp_path / "state.json"
    try:
        state_path.symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="symlink"):
        StateStore(state_path)


def test_state_store_rejects_symlinked_state_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform/filesystem capability
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(ValueError, match="state directory"):
        StateStore(linked / "state.json")


def test_failed_atomic_replace_preserves_last_known_good_state_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.json"
    store = StateStore(path)
    first = AgentRunState(
        run_id="run-first",
        objective="first",
        workspace=str(tmp_path),
    )
    store.save(first)
    original_bytes = path.read_bytes()

    def fail_replace(
        _src: str | bytes,
        _dst: str | bytes,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        assert src_dir_fd is not None
        assert dst_dir_fd is not None
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(fs_authority.os, "rename", fail_replace)
    second = first.model_copy(update={"objective": "second"})

    with pytest.raises(OSError, match="simulated"):
        store.save(second)

    assert path.read_bytes() == original_bytes
    assert StateStore(path).load().objective == "first"
    assert not list(tmp_path.glob(".state.json.*.aiqa.tmp"))


def test_loading_missing_state_is_explicit_failure(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        StateStore(tmp_path / "missing.json").load()
