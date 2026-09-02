from __future__ import annotations

from collections.abc import Mapping
from typing import Any

POLICY_VERSION = "2012-10-17"
TRANSACTION_OPERATION = "TransactWriteItems"
REQUIRED_DIRECT_ACTIONS = frozenset(
    {
        "dynamodb:GetItem",
        "dynamodb:UpdateItem",
    }
)
TRANSACTIONAL_PUT_ACTION = "dynamodb:PutItem"
ALLOWED_ACTIONS = REQUIRED_DIRECT_ACTIONS | {TRANSACTIONAL_PUT_ACTION}


class IamContractError(ValueError):
    """Reviewed DynamoDB runtime policy does not match the narrow gate contract."""


def validate_dynamodb_runtime_policy(
    policy: Mapping[str, Any],
    *,
    table_resource: str,
) -> None:
    """Validate the reviewed DynamoDB allow surface for the external gate.

    This is a deterministic contract linter, not an IAM evaluator. Effective
    deployment authority still requires live IAM simulation/read-back against
    the deployed principal and exact table resource.
    """

    if not isinstance(table_resource, str) or not table_resource or "*" in table_resource:
        raise IamContractError("exact DynamoDB table resource is required")
    if policy.get("Version") != POLICY_VERSION:
        raise IamContractError("IAM policy version is not the reviewed version")

    statements = policy.get("Statement")
    if isinstance(statements, Mapping):
        statement_rows: list[Any] = [statements]
    elif isinstance(statements, list):
        statement_rows = statements
    else:
        raise IamContractError("IAM policy Statement must be an object or list")
    if not statement_rows:
        raise IamContractError("IAM policy contains no statements")

    direct_actions: set[str] = set()
    transactional_put_seen = False

    for index, raw_statement in enumerate(statement_rows):
        if not isinstance(raw_statement, Mapping):
            raise IamContractError(f"statement {index} is not an object")
        effect = raw_statement.get("Effect")
        if effect not in {"Allow", "Deny"}:
            raise IamContractError(f"statement {index} has invalid Effect")
        if effect == "Deny":
            continue

        if "NotAction" in raw_statement or "NotResource" in raw_statement:
            raise IamContractError(
                f"statement {index} uses negative selectors that can expand DynamoDB authority"
            )

        actions = _string_set(raw_statement.get("Action"), label=f"statement {index} Action")
        dynamodb_actions = {
            action for action in actions if action == "*" or action.lower().startswith("dynamodb:")
        }
        if not dynamodb_actions:
            continue
        if dynamodb_actions != actions:
            raise IamContractError(f"statement {index} mixes DynamoDB and non-DynamoDB actions")

        resources = _string_set(
            raw_statement.get("Resource"),
            label=f"statement {index} Resource",
        )
        if resources != {table_resource}:
            raise IamContractError(
                f"statement {index} is not confined to the exact DynamoDB table resource"
            )

        unexpected = actions - ALLOWED_ACTIONS
        if unexpected:
            raise IamContractError(
                f"statement {index} grants DynamoDB actions outside the reviewed runtime contract"
            )

        if TRANSACTIONAL_PUT_ACTION in actions:
            if actions != {TRANSACTIONAL_PUT_ACTION}:
                raise IamContractError(
                    "transaction-only PutItem must be isolated from direct DynamoDB actions"
                )
            _validate_transactional_put_condition(raw_statement.get("Condition"), index=index)
            transactional_put_seen = True
            continue

        if "Condition" in raw_statement:
            raise IamContractError(f"statement {index} conditions required direct DynamoDB actions")
        direct_actions.update(actions)

    missing = REQUIRED_DIRECT_ACTIONS - direct_actions
    if missing:
        raise IamContractError("required direct DynamoDB runtime actions are missing")
    if not transactional_put_seen:
        raise IamContractError("transaction-only PutItem authority is missing")


def _validate_transactional_put_condition(condition: Any, *, index: int) -> None:
    expected = {
        "StringEquals": {
            "dynamodb:EnclosingOperation": TRANSACTION_OPERATION,
        }
    }
    if condition != expected:
        raise IamContractError(
            f"statement {index} PutItem condition is not the exact transaction-only guard"
        )


def _string_set(value: Any, *, label: str) -> set[str]:
    if isinstance(value, str):
        rows = [value]
    elif isinstance(value, list):
        rows = value
    else:
        raise IamContractError(f"{label} must be a string or non-empty string list")
    if not rows or any(not isinstance(row, str) or not row for row in rows):
        raise IamContractError(f"{label} must contain only non-empty strings")
    result = set(rows)
    if len(result) != len(rows):
        raise IamContractError(f"{label} contains duplicate values")
    return result
