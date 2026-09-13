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


def _descriptor_store(tmp_path) -> tuple[StateStore, AgentRunState]:
    if not state_module.descriptor_relative_authority_supported():
        pytest.skip("state publication test requires descriptor-relative authority")
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


def test_descriptor_unreconciled_publication_latches_state_write_uncertainty(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _descriptor_store(tmp_path)
    real_writer = state_module.atomic_write_bytes_confined
    real_reconcile = store._reconcile_publication

    def publish_then_raise(
        root,
        relative_path,
        data,
        *,
        create_parents,
        create_only,
        label,
        expected_root_identity=None,
    ) -> None:
        real_writer(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("post-publication verification unavailable")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_then_raise)
    monkeypatch.setattr(store, "_reconcile_publication", lambda rendered: False)
    state.phase = "AMBIGUOUS_DESCRIPTOR_PUBLICATION"
    with pytest.raises(OSError, match="post-publication verification unavailable"):
        store.save(state)

    published = json.loads(store.path.read_text(encoding="utf-8"))
    assert published["phase"] == "AMBIGUOUS_DESCRIPTOR_PUBLICATION"

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", real_writer)
    monkeypatch.setattr(store, "_reconcile_publication", real_reconcile)
    state.phase = "MUST_NOT_OVERWRITE_AMBIGUOUS_DESCRIPTOR_PUBLICATION"
    with pytest.raises(OSError, match="canonical state write state is uncertain"):
        store.save(state)

    retained = json.loads(store.path.read_text(encoding="utf-8"))
    assert retained["phase"] == "AMBIGUOUS_DESCRIPTOR_PUBLICATION"


def test_descriptor_reconciled_publication_remains_writable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _descriptor_store(tmp_path)
    real_writer = state_module.atomic_write_bytes_confined

    def publish_then_raise(
        root,
        relative_path,
        data,
        *,
        create_parents,
        create_only,
        label,
        expected_root_identity=None,
    ) -> None:
        real_writer(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("post-publication verification unavailable")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_then_raise)
    state.phase = "RECONCILED_PUBLICATION"
    store.save(state)

    reconciled = json.loads(store.path.read_text(encoding="utf-8"))
    assert reconciled["phase"] == "RECONCILED_PUBLICATION"

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", real_writer)
    state.phase = "LATER_VALID"
    store.save(state)

    persisted = json.loads(store.path.read_text(encoding="utf-8"))
    assert persisted["phase"] == "LATER_VALID"


def test_descriptor_interrupted_unreconciled_publication_latches_state_write_uncertainty(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _descriptor_store(tmp_path)
    real_writer = state_module.atomic_write_bytes_confined
    real_reconcile = store._reconcile_publication

    def publish_then_interrupt(
        root,
        relative_path,
        data,
        *,
        create_parents,
        create_only,
        label,
        expected_root_identity=None,
    ) -> None:
        real_writer(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise KeyboardInterrupt("state publication interrupted after visibility")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_then_interrupt)
    monkeypatch.setattr(store, "_reconcile_publication", lambda rendered: False)
    state.phase = "INTERRUPTED_DESCRIPTOR_PUBLICATION"
    with pytest.raises(KeyboardInterrupt, match="state publication interrupted after visibility"):
        store.save(state)

    published = json.loads(store.path.read_text(encoding="utf-8"))
    assert published["phase"] == "INTERRUPTED_DESCRIPTOR_PUBLICATION"

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", real_writer)
    monkeypatch.setattr(store, "_reconcile_publication", real_reconcile)
    state.phase = "MUST_NOT_OVERWRITE_INTERRUPTED_DESCRIPTOR_PUBLICATION"
    with pytest.raises(OSError, match="canonical state write state is uncertain"):
        store.save(state)

    retained = json.loads(store.path.read_text(encoding="utf-8"))
    assert retained["phase"] == "INTERRUPTED_DESCRIPTOR_PUBLICATION"


def test_descriptor_reconciliation_interruption_latches_state_write_uncertainty(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, state = _descriptor_store(tmp_path)
    real_writer = state_module.atomic_write_bytes_confined
    real_reconcile = store._reconcile_publication

    def publish_then_raise(
        root,
        relative_path,
        data,
        *,
        create_parents,
        create_only,
        label,
        expected_root_identity=None,
    ) -> None:
        real_writer(
            root,
            relative_path,
            data,
            create_parents=create_parents,
            create_only=create_only,
            label=label,
            expected_root_identity=expected_root_identity,
        )
        raise OSError("post-publication verification unavailable")

    def interrupt_reconciliation(rendered: bytes) -> bool:
        raise KeyboardInterrupt("state reconciliation interrupted")

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", publish_then_raise)
    monkeypatch.setattr(store, "_reconcile_publication", interrupt_reconciliation)
    state.phase = "INTERRUPTED_RECONCILIATION"
    with pytest.raises(KeyboardInterrupt, match="state reconciliation interrupted"):
        store.save(state)

    published = json.loads(store.path.read_text(encoding="utf-8"))
    assert published["phase"] == "INTERRUPTED_RECONCILIATION"

    monkeypatch.setattr(state_module, "atomic_write_bytes_confined", real_writer)
    monkeypatch.setattr(store, "_reconcile_publication", real_reconcile)
    state.phase = "MUST_NOT_OVERWRITE_INTERRUPTED_RECONCILIATION"
    with pytest.raises(OSError, match="canonical state write state is uncertain"):
        store.save(state)

    retained = json.loads(store.path.read_text(encoding="utf-8"))
    assert retained["phase"] == "INTERRUPTED_RECONCILIATION"
