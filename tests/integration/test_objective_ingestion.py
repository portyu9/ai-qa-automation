from __future__ import annotations

import asyncio
import builtins
from pathlib import Path

import pytest

from ai_qa_automation.agent import run_agent, run_agent_sync
from ai_qa_automation.config import Settings
from ai_qa_automation.runtime.objective_bounds import (
    MAX_OBJECTIVE_UTF8_BYTES,
    ObjectiveBoundsError,
)


@pytest.mark.asyncio
async def test_oversized_objective_is_denied_before_sdk_import_or_artifact_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    artifact_root = tmp_path / "artifacts"
    settings = Settings(
        control_root=Path.cwd(),
        artifact_root=artifact_root,
        max_turns=3,
        max_tool_calls=4,
        max_cost_usd=0.5,
    )
    real_import = builtins.__import__
    sdk_import_attempted = False

    def guarded_import(
        name: str,
        globals=None,
        locals=None,
        fromlist=(),
        level: int = 0,
    ):
        nonlocal sdk_import_attempted
        if name == "claude_agent_sdk":
            sdk_import_attempted = True
            raise AssertionError("SDK import must not occur for a denied objective")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)

    with pytest.raises(ObjectiveBoundsError) as caught:
        await run_agent("x" * (MAX_OBJECTIVE_UTF8_BYTES + 1), target, settings)

    assert caught.value.code == "objective_bytes"
    assert sdk_import_attempted is False
    assert artifact_root.exists() is False


@pytest.mark.asyncio
async def test_whitespace_objective_is_denied_before_runtime_artifacts(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    artifact_root = tmp_path / "artifacts"
    settings = Settings(control_root=Path.cwd(), artifact_root=artifact_root)

    with pytest.raises(ObjectiveBoundsError) as caught:
        await run_agent(" \t\n", target, settings)

    assert caught.value.code == "objective_empty"
    assert artifact_root.exists() is False


def test_sync_entry_rejects_invalid_objective_before_event_loop_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    event_loop_started = False

    def forbidden_asyncio_run(_coroutine):
        nonlocal event_loop_started
        event_loop_started = True
        raise AssertionError("asyncio.run must not execute for a denied objective")

    monkeypatch.setattr(asyncio, "run", forbidden_asyncio_run)

    with pytest.raises(ObjectiveBoundsError) as caught:
        run_agent_sync("", target)

    assert caught.value.code == "objective_empty"
    assert event_loop_started is False
