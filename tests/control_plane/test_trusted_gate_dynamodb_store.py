from __future__ import annotations

import copy
from typing import Any

import pytest

from scripts.trusted_gate_service.dynamodb_store import (
    DeliveryStoreTransportError,
    DynamoDeliveryStore,
)
from scripts.trusted_gate_service.store import MAX_RECORDS

DELIVERY = "00000000-0000-0000-0000-000000000001"
RUN_ID = 918


class AwsError(Exception):
    def __init__(self, code: str, *, cancellation_reasons: list[str] | None = None) -> None:
        super().__init__(code)
        self.response: dict[str, Any] = {"Error": {"Code": code}}
        if cancellation_reasons is not None:
            self.response["CancellationReasons"] = [
                {"Code": reason} for reason in cancellation_reasons
            ]


class FakeDynamo:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}
        self.record_count = 0
        self.read_error: str | None = None
        self.update_error: str | None = None
        self.transaction_error_reasons: list[str] | None = None
        self.fail_next_update = False

    @staticmethod
    def _id(key: dict[str, Any]) -> str:
        return key["pk"]["S"]

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs["ConsistentRead"] is True
        if self.read_error is not None:
            raise AwsError(self.read_error)
        item = self.items.get(self._id(kwargs["Key"]))
        return {} if item is None else {"Item": copy.deepcopy(item)}

    def transact_write_items(self, **kwargs: Any) -> None:
        if self.transaction_error_reasons is not None:
            raise AwsError(
                "TransactionCanceledException",
                cancellation_reasons=self.transaction_error_reasons,
            )
        put = kwargs["TransactItems"][1]["Put"]
        item = copy.deepcopy(put["Item"])
        key = self._id(item)
        if key in self.items:
            raise AwsError(
                "TransactionCanceledException",
                cancellation_reasons=["None", "ConditionalCheckFailed"],
            )
        if self.record_count >= MAX_RECORDS:
            raise AwsError(
                "TransactionCanceledException",
                cancellation_reasons=["ConditionalCheckFailed", "None"],
            )
        self.items[key] = item
        self.record_count += 1

    def update_item(self, **kwargs: Any) -> None:
        if self.update_error is not None:
            raise AwsError(self.update_error)
        if self.fail_next_update:
            self.fail_next_update = False
            raise AwsError("ConditionalCheckFailedException")
        key = self._id(kwargs["Key"])
        item = self.items[key]
        values = kwargs["ExpressionAttributeValues"]
        condition = kwargs["ConditionExpression"]
        state = item["state"]["S"]
        if ":expected" in values and state != values[":expected"]["S"]:
            raise AwsError("ConditionalCheckFailedException")
        if ":processing" in values and "#state=:processing" in condition:
            if state != "PROCESSING":
                raise AwsError("ConditionalCheckFailedException")
        if ":attempt" in values and item["attempt"] != values[":attempt"]:
            raise AwsError("ConditionalCheckFailedException")
        if ":last" in values and item["last_attempt_epoch"] != values[":last"]:
            raise AwsError("ConditionalCheckFailedException")
        if item["terminal"]["BOOL"] and ":false" in values:
            raise AwsError("ConditionalCheckFailedException")
        if item["publication_started"]["BOOL"] and ":false" in values:
            raise AwsError("ConditionalCheckFailedException")

        now = values.get(":now")
        if now is not None:
            item["updated_epoch"] = now
        if ":subject" in values:
            item["subject_json"] = values[":subject"]
            item["policy_id"] = values[":policy"]
            item["target_url"] = values[":target"]
        elif ":retryable" in values:
            item["state"] = values[":retryable"]
            item["error_code"] = values[":error"]
        elif ":blocked" in values:
            item["state"] = values[":blocked"]
            item["terminal"] = {"BOOL": True}
            item["error_code"] = values[":error"]
        elif ":success" in values:
            if not item["publication_started"]["BOOL"]:
                raise AwsError("ConditionalCheckFailedException")
            item["state"] = values[":success"]
            item["terminal"] = {"BOOL": True}
            item["publication_observed"] = {"BOOL": True}
        elif ":publishing" in values:
            if not all(name in item for name in ("subject_json", "policy_id", "target_url")):
                raise AwsError("ConditionalCheckFailedException")
            item["state"] = values[":publishing"]
            item["publication_started"] = {"BOOL": True}
        elif ":next" in values:
            item["state"] = values[":processing"]
            item["attempt"] = values[":next"]
            item["last_attempt_epoch"] = values[":now"]
            for name in ("subject_json", "policy_id", "target_url"):
                item.pop(name, None)
            if ":error" in values:
                item["error_code"] = values[":error"]
            else:
                item.pop("error_code", None)


def _store(client: FakeDynamo, now: list[float]) -> DynamoDeliveryStore:
    return DynamoDeliveryStore(client=client, table_name="state", clock=lambda: now[0])


def test_duplicate_processing_delivery_has_no_second_owner() -> None:
    client = FakeDynamo()
    now = [100.0]
    store = _store(client, now)
    first = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    duplicate = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert first.state == "PROCESSING"
    assert duplicate.state == "BUSY"
    assert client.record_count == 1


def test_stale_processing_lease_is_recovered_with_bounded_attempt() -> None:
    client = FakeDynamo()
    now = [100.0]
    store = _store(client, now)
    store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    now[0] = 161.0
    recovered = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert recovered.state == "PROCESSING"
    assert recovered.attempt == 2
    assert store.acquire(delivery_id=DELIVERY, run_id=RUN_ID).state == "BUSY"


def test_conditional_reacquire_race_returns_busy_without_masking_transport() -> None:
    client = FakeDynamo()
    now = [100.0]
    store = _store(client, now)
    store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    now[0] = 161.0
    client.fail_next_update = True
    assert store.acquire(delivery_id=DELIVERY, run_id=RUN_ID).state == "BUSY"

    client.update_error = "ThrottlingException"
    with pytest.raises(DeliveryStoreTransportError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)


def test_delivery_id_cannot_change_workflow_run() -> None:
    client = FakeDynamo()
    store = _store(client, [100.0])
    store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    with pytest.raises(RuntimeError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID + 1)


def test_publication_intent_is_durable_and_terminal_success_is_idempotent() -> None:
    client = FakeDynamo()
    store = _store(client, [100.0])
    store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    store.bind_subject(
        delivery_id=DELIVERY,
        subject={"head_sha": "1" * 40},
        policy_id="policy-1",
        target_url="https://github.com/portyu9/ai-qa-automation/actions/runs/918",
    )
    assert store.begin_publication(delivery_id=DELIVERY).state == "PUBLISHING"
    assert store.acquire(delivery_id=DELIVERY, run_id=RUN_ID).state == "PUBLISHING"
    store.complete_publication(delivery_id=DELIVERY)
    store.complete_publication(delivery_id=DELIVERY)
    terminal = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert terminal.state == "SUCCESS"
    assert terminal.terminal


def test_retry_budget_exhaustion_becomes_terminal_blocked() -> None:
    client = FakeDynamo()
    now = [100.0]
    store = _store(client, now)
    lease = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert lease.attempt == 1
    for expected in (2, 3):
        store.mark_retryable(delivery_id=DELIVERY, error_code="transport")
        now[0] += 31
        lease = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
        assert lease.attempt == expected
    store.mark_retryable(delivery_id=DELIVERY, error_code="transport")
    now[0] += 31
    exhausted = store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert exhausted.state == "BLOCKED"
    assert exhausted.terminal


def test_store_record_bound_fails_closed() -> None:
    client = FakeDynamo()
    client.record_count = MAX_RECORDS
    store = _store(client, [100.0])
    with pytest.raises(RuntimeError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert not client.items


def test_transaction_conflict_is_infrastructure_not_record_bound() -> None:
    client = FakeDynamo()
    client.transaction_error_reasons = ["TransactionConflict", "None"]
    store = _store(client, [100.0])
    with pytest.raises(DeliveryStoreTransportError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    assert not client.items


def test_ambiguous_transaction_cancellation_is_infrastructure() -> None:
    class AmbiguousTransactionClient(FakeDynamo):
        def transact_write_items(self, **kwargs: Any) -> None:
            del kwargs
            raise AwsError("TransactionCanceledException")

    store = _store(AmbiguousTransactionClient(), [100.0])
    with pytest.raises(DeliveryStoreTransportError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)


def test_dynamodb_throttling_is_distinct_transport_failure() -> None:
    client = FakeDynamo()
    client.read_error = "ThrottlingException"
    store = _store(client, [100.0])
    with pytest.raises(DeliveryStoreTransportError):
        store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)


def test_malformed_persisted_item_fails_closed() -> None:
    client = FakeDynamo()
    store = _store(client, [100.0])
    store.acquire(delivery_id=DELIVERY, run_id=RUN_ID)
    client.items[f"DELIVERY#{DELIVERY}"]["unexpected"] = {"S": "authority-drift"}
    with pytest.raises(RuntimeError):
        store.load(DELIVERY)
