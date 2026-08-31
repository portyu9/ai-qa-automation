from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from scripts.trusted_gate_service.store import DeliveryStore

DELIVERY = "00000000-0000-0000-0000-000000000001"
RUN_ID = 918
HEAD = "1" * 40


def test_terminal_duplicate_never_reexecutes() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = DeliveryStore(Path(td) / "store.sqlite3")
        first = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        assert first.state == "PROCESSING"
        store.mark_blocked(delivery_id=DELIVERY, error_code="policy")
        second = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        assert second.terminal
        assert second.state == "BLOCKED"


def test_store_rejects_group_world_writable_parent() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        root.chmod(0o777)
        try:
            with pytest.raises(ValueError):
                DeliveryStore(root / "store.sqlite3")
        finally:
            root.chmod(0o700)


def test_delivery_id_cannot_be_reused_for_different_run() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = DeliveryStore(Path(td) / "store.sqlite3")
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        with pytest.raises(RuntimeError):
            store.acquire(delivery_id=DELIVERY, run_id=RUN_ID + 1)


def test_publication_intent_is_irreversible_without_observation() -> None:
    with tempfile.TemporaryDirectory() as td:
        store = DeliveryStore(Path(td) / "store.sqlite3")
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        store.bind_subject(
            delivery_id=DELIVERY,
            subject={"head_sha": HEAD},
            policy_id="p1",
            target_url="https://example.invalid/run",
        )
        lease = store.begin_publication(delivery_id=DELIVERY)
        assert lease.state == "PUBLISHING"
        duplicate = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        assert duplicate.state == "PUBLISHING"
        with pytest.raises(RuntimeError):
            store.mark_retryable(delivery_id=DELIVERY, error_code="transport")
