from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from .store import MAX_RECORDS, RETRY_DELAY_SECONDS, RETRY_LIMIT, DeliveryLease

PROCESSING_LEASE_SECONDS = 60
MAX_SUBJECT_JSON_BYTES = 64 * 1024
MAX_POLICY_ID_BYTES = 256
MAX_TARGET_URL_BYTES = 2048
MAX_ERROR_CODE_BYTES = 128

_RETRYABLE_AWS_ERRORS = {
    "InternalServerError",
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "ThrottlingException",
    "TransactionInProgressException",
}
_RETRYABLE_TRANSACTION_CANCEL_REASONS = {
    "ProvisionedThroughputExceeded",
    "ThrottlingError",
    "TransactionConflict",
}
_NONRETRYABLE_TRANSACTION_CANCEL_REASONS = {
    "ItemCollectionSizeLimitExceeded",
    "ValidationError",
}


class DeliveryStoreTransportError(Exception):
    """DynamoDB transport/infrastructure failure that must not become policy truth."""


class _ConditionalStateError(RuntimeError):
    """A conditional state transition lost ownership to another invocation."""


class DynamoDeliveryStore:
    """DynamoDB delivery state with atomic ownership and a hard record-count bound."""

    def __init__(
        self,
        *,
        client: Any,
        table_name: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not table_name or len(table_name) > 255:
            raise ValueError("DynamoDB table name is required")
        self._client = client
        self._table_name = table_name
        self._clock = clock

    def acquire(self, *, delivery_id: str, run_id: int) -> DeliveryLease:
        self._validate_identity(delivery_id, run_id)
        now = int(self._clock())
        row = self._get(delivery_id)
        if row is None:
            if self._create(delivery_id=delivery_id, run_id=run_id, now=now):
                return DeliveryLease(delivery_id, run_id, 1, "PROCESSING", False, None, None, None)
            row = self._get(delivery_id)
            if row is None:
                raise RuntimeError(
                    "delivery record bound reached or concurrent create was unresolved"
                )

        lease = self._lease(row, delivery_id=delivery_id)
        if lease.run_id != run_id:
            raise RuntimeError("webhook delivery id was reused for a different workflow run")
        if lease.terminal or lease.state == "PUBLISHING":
            return lease

        if lease.state == "PROCESSING":
            last_attempt = self._number(row, "last_attempt_epoch", minimum=0)
            if now - last_attempt < PROCESSING_LEASE_SECONDS:
                return replace(lease, state="BUSY")
            return self._reacquire(
                row=row,
                lease=lease,
                now=now,
                expected_state="PROCESSING",
                carried_error="processing_lease_expired",
            )

        if lease.state != "RETRYABLE":
            raise RuntimeError("delivery has an unsupported nonterminal state")
        last_attempt = self._number(row, "last_attempt_epoch", minimum=0)
        if now - last_attempt < RETRY_DELAY_SECONDS:
            return lease
        return self._reacquire(
            row=row,
            lease=lease,
            now=now,
            expected_state="RETRYABLE",
            carried_error=None,
        )

    def bind_subject(
        self,
        *,
        delivery_id: str,
        subject: dict[str, Any],
        policy_id: str,
        target_url: str,
    ) -> None:
        rendered = json.dumps(subject, separators=(",", ":"), sort_keys=True)
        if len(rendered.encode()) > MAX_SUBJECT_JSON_BYTES:
            raise RuntimeError("bound subject exceeds configured size")
        if not policy_id or len(policy_id.encode()) > MAX_POLICY_ID_BYTES:
            raise RuntimeError("policy id is missing or too large")
        if not target_url or len(target_url.encode()) > MAX_TARGET_URL_BYTES:
            raise RuntimeError("target URL is missing or too large")
        self._conditional_update(
            delivery_id=delivery_id,
            update_expression=(
                "SET subject_json=:subject, policy_id=:policy, target_url=:target, updated_epoch=:now"
            ),
            condition_expression=(
                "#state=:processing AND terminal=:false AND publication_started=:false"
            ),
            names={"#state": "state"},
            values={
                ":subject": {"S": rendered},
                ":policy": {"S": policy_id},
                ":target": {"S": target_url},
                ":now": {"N": str(int(self._clock()))},
                ":processing": {"S": "PROCESSING"},
                ":false": {"BOOL": False},
            },
            failure="delivery is not mutable PROCESSING state",
        )

    def mark_retryable(self, *, delivery_id: str, error_code: str) -> None:
        self._conditional_update(
            delivery_id=delivery_id,
            update_expression="SET #state=:retryable, error_code=:error, updated_epoch=:now",
            condition_expression=(
                "#state=:processing AND terminal=:false AND publication_started=:false"
            ),
            names={"#state": "state"},
            values={
                ":retryable": {"S": "RETRYABLE"},
                ":processing": {"S": "PROCESSING"},
                ":error": {"S": self._bounded_error(error_code)},
                ":now": {"N": str(int(self._clock()))},
                ":false": {"BOOL": False},
            },
            failure="cannot retry after publication or terminal transition",
        )

    def mark_blocked(self, *, delivery_id: str, error_code: str) -> None:
        self._conditional_update(
            delivery_id=delivery_id,
            update_expression=(
                "SET #state=:blocked, terminal=:true, error_code=:error, updated_epoch=:now"
            ),
            condition_expression=(
                "#state=:processing AND terminal=:false AND publication_started=:false"
            ),
            names={"#state": "state"},
            values={
                ":blocked": {"S": "BLOCKED"},
                ":processing": {"S": "PROCESSING"},
                ":true": {"BOOL": True},
                ":false": {"BOOL": False},
                ":error": {"S": self._bounded_error(error_code)},
                ":now": {"N": str(int(self._clock()))},
            },
            failure="cannot block after publication or terminal transition",
        )

    def begin_publication(self, *, delivery_id: str) -> DeliveryLease:
        self._conditional_update(
            delivery_id=delivery_id,
            update_expression=(
                "SET #state=:publishing, publication_started=:true, updated_epoch=:now"
            ),
            condition_expression=(
                "#state=:processing AND terminal=:false AND publication_started=:false "
                "AND attribute_exists(subject_json) AND attribute_exists(policy_id) "
                "AND attribute_exists(target_url)"
            ),
            names={"#state": "state"},
            values={
                ":publishing": {"S": "PUBLISHING"},
                ":processing": {"S": "PROCESSING"},
                ":true": {"BOOL": True},
                ":false": {"BOOL": False},
                ":now": {"N": str(int(self._clock()))},
            },
            failure="delivery lacks bound subject/policy before publication",
        )
        lease = self.load(delivery_id)
        if lease is None or lease.state != "PUBLISHING":
            raise RuntimeError("publication intent could not be re-read")
        return lease

    def complete_publication(self, *, delivery_id: str) -> None:
        self._conditional_update(
            delivery_id=delivery_id,
            update_expression=(
                "SET #state=:success, terminal=:true, publication_observed=:true, updated_epoch=:now"
            ),
            condition_expression=(
                "publication_started=:true AND (#state=:publishing OR #state=:success)"
            ),
            names={"#state": "state"},
            values={
                ":success": {"S": "SUCCESS"},
                ":publishing": {"S": "PUBLISHING"},
                ":true": {"BOOL": True},
                ":now": {"N": str(int(self._clock()))},
            },
            failure="publication completion lacks durable publication intent",
        )

    def load(self, delivery_id: str) -> DeliveryLease | None:
        self._validate_delivery_id(delivery_id)
        row = self._get(delivery_id)
        return None if row is None else self._lease(row, delivery_id=delivery_id)

    def _create(self, *, delivery_id: str, run_id: int, now: int) -> bool:
        item = {
            **self._key(delivery_id),
            "run_id": {"N": str(run_id)},
            "state": {"S": "PROCESSING"},
            "attempt": {"N": "1"},
            "last_attempt_epoch": {"N": str(now)},
            "terminal": {"BOOL": False},
            "publication_started": {"BOOL": False},
            "publication_observed": {"BOOL": False},
            "created_epoch": {"N": str(now)},
            "updated_epoch": {"N": str(now)},
        }
        try:
            self._client.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": self._table_name,
                            "Key": self._meta_key(),
                            "UpdateExpression": (
                                "SET record_count=if_not_exists(record_count,:zero)+:one"
                            ),
                            "ConditionExpression": (
                                "attribute_not_exists(record_count) OR record_count < :max"
                            ),
                            "ExpressionAttributeValues": {
                                ":zero": {"N": "0"},
                                ":one": {"N": "1"},
                                ":max": {"N": str(MAX_RECORDS)},
                            },
                        }
                    },
                    {
                        "Put": {
                            "TableName": self._table_name,
                            "Item": item,
                            "ConditionExpression": "attribute_not_exists(pk)",
                        }
                    },
                ]
            )
        except Exception as exc:
            if self._aws_error_code(exc) == "TransactionCanceledException":
                cancellation = self._transaction_cancellation_kind(exc)
                if cancellation == "conditional":
                    return False
                if cancellation in {"retryable", "ambiguous"}:
                    raise DeliveryStoreTransportError(
                        "DynamoDB transaction infrastructure failure during create delivery"
                    ) from exc
                raise RuntimeError(
                    "DynamoDB non-retryable transaction failure during create delivery"
                ) from exc
            self._raise_aws(exc, operation="create delivery")
        return True

    def _reacquire(
        self,
        *,
        row: dict[str, Any],
        lease: DeliveryLease,
        now: int,
        expected_state: str,
        carried_error: str | None,
    ) -> DeliveryLease:
        if lease.attempt >= RETRY_LIMIT:
            try:
                self._conditional_update(
                    delivery_id=lease.delivery_id,
                    update_expression=(
                        "SET #state=:blocked, terminal=:true, error_code=:error, updated_epoch=:now"
                    ),
                    condition_expression=(
                        "#state=:expected AND attempt=:attempt AND terminal=:false "
                        "AND publication_started=:false"
                    ),
                    names={"#state": "state"},
                    values={
                        ":blocked": {"S": "BLOCKED"},
                        ":expected": {"S": expected_state},
                        ":attempt": {"N": str(lease.attempt)},
                        ":true": {"BOOL": True},
                        ":false": {"BOOL": False},
                        ":error": {"S": "retry_budget_exhausted"},
                        ":now": {"N": str(now)},
                    },
                    failure="retry exhaustion raced with another owner",
                )
            except _ConditionalStateError as exc:
                latest = self.load(lease.delivery_id)
                if latest is not None:
                    return latest
                raise RuntimeError("delivery disappeared after retry-exhaustion race") from exc
            latest = self.load(lease.delivery_id)
            if latest is None:
                raise RuntimeError("exhausted delivery disappeared")
            return latest

        next_attempt = lease.attempt + 1
        update = (
            "SET #state=:processing, attempt=:next, last_attempt_epoch=:now, updated_epoch=:now"
        )
        values: dict[str, dict[str, Any]] = {
            ":processing": {"S": "PROCESSING"},
            ":expected": {"S": expected_state},
            ":attempt": {"N": str(lease.attempt)},
            ":next": {"N": str(next_attempt)},
            ":last": row["last_attempt_epoch"],
            ":now": {"N": str(now)},
            ":false": {"BOOL": False},
        }
        if carried_error is not None:
            update += ", error_code=:error"
            values[":error"] = {"S": self._bounded_error(carried_error)}
            update += " REMOVE subject_json, policy_id, target_url"
        else:
            update += " REMOVE subject_json, policy_id, target_url, error_code"
        try:
            self._conditional_update(
                delivery_id=lease.delivery_id,
                update_expression=update,
                condition_expression=(
                    "#state=:expected AND attempt=:attempt AND last_attempt_epoch=:last "
                    "AND terminal=:false AND publication_started=:false"
                ),
                names={"#state": "state"},
                values=values,
                failure="delivery reacquisition raced with another owner",
            )
        except _ConditionalStateError as exc:
            latest = self.load(lease.delivery_id)
            if latest is None:
                raise RuntimeError("delivery disappeared after reacquisition race") from exc
            return replace(latest, state="BUSY") if latest.state == "PROCESSING" else latest
        latest = self.load(lease.delivery_id)
        if latest is None:
            raise RuntimeError("reacquired delivery disappeared")
        return latest

    def _get(self, delivery_id: str) -> dict[str, Any] | None:
        try:
            response = self._client.get_item(
                TableName=self._table_name,
                Key=self._key(delivery_id),
                ConsistentRead=True,
            )
        except Exception as exc:
            self._raise_aws(exc, operation="read delivery")
        item = response.get("Item")
        if item is None:
            return None
        if not isinstance(item, dict):
            raise RuntimeError("DynamoDB returned malformed delivery item")
        return item

    def _conditional_update(
        self,
        *,
        delivery_id: str,
        update_expression: str,
        condition_expression: str,
        names: dict[str, str],
        values: dict[str, dict[str, Any]],
        failure: str,
    ) -> None:
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key=self._key(delivery_id),
                UpdateExpression=update_expression,
                ConditionExpression=condition_expression,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except Exception as exc:
            if self._aws_error_code(exc) == "ConditionalCheckFailedException":
                raise _ConditionalStateError(failure) from exc
            self._raise_aws(exc, operation="update delivery")

    @staticmethod
    def _aws_error_code(exc: Exception) -> str:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return ""
        error = response.get("Error")
        if not isinstance(error, dict):
            return ""
        code = error.get("Code")
        return code if isinstance(code, str) else ""

    @staticmethod
    def _transaction_cancellation_kind(exc: Exception) -> str:
        response = getattr(exc, "response", None)
        if not isinstance(response, dict):
            return "ambiguous"
        reasons = response.get("CancellationReasons")
        if not isinstance(reasons, list) or len(reasons) != 2:
            return "ambiguous"
        codes: list[str] = []
        for reason in reasons:
            if not isinstance(reason, dict):
                return "ambiguous"
            code = reason.get("Code")
            if not isinstance(code, str):
                return "ambiguous"
            codes.append(code)
        code_set = set(codes)
        if (
            code_set.issubset({"None", "ConditionalCheckFailed"})
            and "ConditionalCheckFailed" in code_set
        ):
            return "conditional"
        if code_set & _RETRYABLE_TRANSACTION_CANCEL_REASONS:
            return "retryable"
        if code_set & _NONRETRYABLE_TRANSACTION_CANCEL_REASONS:
            return "nonretryable"
        return "ambiguous"

    def _raise_aws(self, exc: Exception, *, operation: str) -> None:
        code = self._aws_error_code(exc)
        if not code or code in _RETRYABLE_AWS_ERRORS:
            raise DeliveryStoreTransportError(
                f"DynamoDB transport failure during {operation}"
            ) from exc
        raise RuntimeError(f"DynamoDB non-retryable failure during {operation}") from exc

    @classmethod
    def _lease(cls, row: dict[str, Any], *, delivery_id: str) -> DeliveryLease:
        expected_key = cls._key(delivery_id)
        if row.get("pk") != expected_key["pk"] or row.get("sk") != expected_key["sk"]:
            raise RuntimeError("DynamoDB delivery key identity mismatch")
        required = {
            "pk",
            "sk",
            "run_id",
            "state",
            "attempt",
            "last_attempt_epoch",
            "terminal",
            "publication_started",
            "publication_observed",
            "created_epoch",
            "updated_epoch",
        }
        optional = {"subject_json", "policy_id", "target_url", "error_code"}
        if not required.issubset(row) or not set(row).issubset(required | optional):
            raise RuntimeError("DynamoDB delivery fields are not exact")
        state = cls._string(row, "state", max_bytes=32)
        if state not in {"PROCESSING", "RETRYABLE", "PUBLISHING", "SUCCESS", "BLOCKED"}:
            raise RuntimeError("DynamoDB delivery state is invalid")
        attempt = cls._number(row, "attempt", minimum=1)
        if attempt > RETRY_LIMIT:
            raise RuntimeError("DynamoDB delivery attempt exceeds retry bound")
        terminal = cls._boolean(row, "terminal")
        publication_started = cls._boolean(row, "publication_started")
        publication_observed = cls._boolean(row, "publication_observed")
        if terminal != (state in {"SUCCESS", "BLOCKED"}):
            raise RuntimeError("DynamoDB terminal flag disagrees with delivery state")
        if publication_started != (state in {"PUBLISHING", "SUCCESS"}):
            raise RuntimeError("DynamoDB publication flag disagrees with delivery state")
        if publication_observed != (state == "SUCCESS"):
            raise RuntimeError("DynamoDB publication observation disagrees with delivery state")
        cls._number(row, "last_attempt_epoch", minimum=0)
        created = cls._number(row, "created_epoch", minimum=0)
        updated = cls._number(row, "updated_epoch", minimum=created)
        if updated < created:
            raise RuntimeError("DynamoDB delivery timestamps are inconsistent")
        error_code = cls._optional_string(row, "error_code", MAX_ERROR_CODE_BYTES)
        if state == "RETRYABLE" and error_code is None:
            raise RuntimeError("retryable DynamoDB delivery lacks an error code")
        return DeliveryLease(
            delivery_id=delivery_id,
            run_id=cls._number(row, "run_id", minimum=1),
            attempt=attempt,
            state=state,
            terminal=terminal,
            subject_json=cls._optional_string(row, "subject_json", MAX_SUBJECT_JSON_BYTES),
            policy_id=cls._optional_string(row, "policy_id", MAX_POLICY_ID_BYTES),
            target_url=cls._optional_string(row, "target_url", MAX_TARGET_URL_BYTES),
        )

    @staticmethod
    def _key(delivery_id: str) -> dict[str, dict[str, str]]:
        DynamoDeliveryStore._validate_delivery_id(delivery_id)
        return {"pk": {"S": f"DELIVERY#{delivery_id}"}, "sk": {"S": "STATE"}}

    @staticmethod
    def _meta_key() -> dict[str, dict[str, str]]:
        return {"pk": {"S": "META"}, "sk": {"S": "STORE"}}

    @staticmethod
    def _validate_identity(delivery_id: str, run_id: int) -> None:
        DynamoDeliveryStore._validate_delivery_id(delivery_id)
        if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
            raise ValueError("workflow run id must be a positive integer")

    @staticmethod
    def _validate_delivery_id(delivery_id: str) -> None:
        if not isinstance(delivery_id, str) or not delivery_id or len(delivery_id) > 128:
            raise ValueError("delivery id is missing or too large")

    @staticmethod
    def _bounded_error(error_code: str) -> str:
        if not isinstance(error_code, str) or not error_code:
            raise ValueError("delivery error code must be non-empty")
        encoded = error_code.encode("utf-8")
        if len(encoded) <= MAX_ERROR_CODE_BYTES:
            return error_code
        return encoded[:MAX_ERROR_CODE_BYTES].decode("utf-8", errors="ignore") or "bounded_error"

    @staticmethod
    def _string(row: dict[str, Any], key: str, *, max_bytes: int) -> str:
        value = row.get(key)
        if not isinstance(value, dict) or set(value) != {"S"}:
            raise RuntimeError(f"DynamoDB field {key} is not a string")
        rendered = value["S"]
        if not isinstance(rendered, str) or not rendered or len(rendered.encode()) > max_bytes:
            raise RuntimeError(f"DynamoDB field {key} is invalid")
        return rendered

    @classmethod
    def _optional_string(cls, row: dict[str, Any], key: str, max_bytes: int) -> str | None:
        if key not in row:
            return None
        return cls._string(row, key, max_bytes=max_bytes)

    @staticmethod
    def _number(row: dict[str, Any], key: str, *, minimum: int) -> int:
        value = row.get(key)
        if not isinstance(value, dict) or set(value) != {"N"}:
            raise RuntimeError(f"DynamoDB field {key} is not a number")
        rendered = value["N"]
        if not isinstance(rendered, str) or not rendered.isdigit():
            raise RuntimeError(f"DynamoDB field {key} is malformed")
        parsed = int(rendered)
        if parsed < minimum:
            raise RuntimeError(f"DynamoDB field {key} is below its minimum")
        return parsed

    @staticmethod
    def _boolean(row: dict[str, Any], key: str) -> bool:
        value = row.get(key)
        if (
            not isinstance(value, dict)
            or set(value) != {"BOOL"}
            or not isinstance(value["BOOL"], bool)
        ):
            raise RuntimeError(f"DynamoDB field {key} is not a boolean")
        return value["BOOL"]
