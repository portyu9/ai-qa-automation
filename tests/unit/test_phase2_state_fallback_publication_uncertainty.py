from __future__ import annotations

import json

import pytest

import ai_qa_automation.state as state_module
from ai_qa_automation.models import AgentRunState
from ai_qa_automation.state import StateStore


def _fallback_store(tmp_path, monkeypatch: pytest.MonkeyPatch) -> tuple[StateStore, AgentRunState]:
    monkeypatch.setattr(state_module, "descriptor_relative_authority_supported", lambda: False)
    store = StateStore(tmp_path / "state.json")
    state = AgentRunState(objective="state publication uncertainty", workspace=str(tmp_path))
    store.save(state)
    return store, state


def test_fallback_post_publication_failure_latches_state_write_uncertainty(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _fallback_store(tmp_path, monkeypatch)
    real_revalidate = store._revalidate_parent
    calls = 0

    def fail_after_replace() -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ValueError("post-publication parent revalidation failed")
        real_revalidate()

    monkeypatch.setattr(store, "_revalidate_parent", fail_after_replace)
    state.phase = "AMBIGUOUS_PUBLICATION"
    with pytest.raises(ValueError, match="post-publication parent revalidation failed"):
        store.save(state)

    published = json.loads(store.path.read_text(encoding="utf-8"))
    assert published["phase"] == "AMBIGUOUS_PUBLICATION"

    monkeypatch.setattr(store, "_revalidate_parent", real_revalidate)
    state.phase = "MUST_NOT_OVERWRITE_AMBIGUOUS_PUBLICATION"
    with pytest.raises(OSError, match="canonical state write state is uncertain"):
        store.save(state)

    retained = json.loads(store.path.read_text(encoding="utf-8"))
    assert retained["phase"] == "AMBIGUOUS_PUBLICATION"


def test_fallback_pre_publication_failure_remains_retryable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _fallback_store(tmp_path, monkeypatch)
    real_revalidate = store._revalidate_parent
    calls = 0

    def fail_before_replace() -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("pre-publication parent revalidation failed")
        real_revalidate()

    monkeypatch.setattr(store, "_revalidate_parent", fail_before_replace)
    state.phase = "NEVER_PUBLISHED"
    with pytest.raises(ValueError, match="pre-publication parent revalidation failed"):
        store.save(state)

    retained = json.loads(store.path.read_text(encoding="utf-8"))
    assert retained["phase"] != "NEVER_PUBLISHED"

    monkeypatch.setattr(store, "_revalidate_parent", real_revalidate)
    state.phase = "LATER_VALID"
    store.save(state)

    persisted = json.loads(store.path.read_text(encoding="utf-8"))
    assert persisted["phase"] == "LATER_VALID"
