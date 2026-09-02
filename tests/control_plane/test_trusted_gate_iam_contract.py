from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.trusted_gate_service.iam_contract import (
    IamContractError,
    validate_dynamodb_runtime_policy,
)

TABLE_RESOURCE = "EXACT_TABLE_RESOURCE"


def _valid_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
                "Resource": TABLE_RESOURCE,
            },
            {
                "Effect": "Allow",
                "Action": "dynamodb:PutItem",
                "Resource": TABLE_RESOURCE,
                "Condition": {
                    "StringEquals": {
                        "dynamodb:EnclosingOperation": "TransactWriteItems",
                    }
                },
            },
            {
                "Effect": "Allow",
                "Action": "ssm:GetParameter",
                "Resource": "EXACT_PARAMETER_RESOURCE",
            },
        ],
    }


def test_valid_contract_requires_direct_reads_updates_and_transaction_only_put() -> None:
    validate_dynamodb_runtime_policy(_valid_policy(), table_resource=TABLE_RESOURCE)


@pytest.mark.parametrize("missing_action", ["dynamodb:GetItem", "dynamodb:UpdateItem"])
def test_required_direct_action_cannot_be_omitted(missing_action: str) -> None:
    policy = _valid_policy()
    policy["Statement"][0]["Action"].remove(missing_action)
    with pytest.raises(IamContractError, match="required direct"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


def test_transactional_put_cannot_be_omitted() -> None:
    policy = _valid_policy()
    del policy["Statement"][1]
    with pytest.raises(IamContractError, match="transaction-only PutItem authority is missing"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


def test_standalone_putitem_is_rejected() -> None:
    policy = _valid_policy()
    del policy["Statement"][1]["Condition"]
    with pytest.raises(IamContractError, match="transaction-only guard"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


@pytest.mark.parametrize(
    "condition",
    [
        {"StringEquals": {"dynamodb:EnclosingOperation": "BatchWriteItem"}},
        {"StringLike": {"dynamodb:EnclosingOperation": "Transact*"}},
        {
            "StringEquals": {
                "dynamodb:EnclosingOperation": ["TransactWriteItems"],
            }
        },
        {
            "StringEquals": {
                "dynamodb:EnclosingOperation": "TransactWriteItems",
                "aws:RequestedRegion": "example-region",
            }
        },
    ],
)
def test_putitem_condition_must_be_exact(condition: dict[str, Any]) -> None:
    policy = _valid_policy()
    policy["Statement"][1]["Condition"] = condition
    with pytest.raises(IamContractError, match="transaction-only guard"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


@pytest.mark.parametrize(
    "action",
    [
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:CreateTable",
        "dynamodb:UpdateTable",
        "dynamodb:DeleteTable",
        "dynamodb:TransactWriteItems",
        "dynamodb:*",
        "*",
    ],
)
def test_unreviewed_or_broad_dynamodb_actions_are_rejected(action: str) -> None:
    policy = _valid_policy()
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Action": action,
            "Resource": TABLE_RESOURCE,
        }
    )
    with pytest.raises(IamContractError):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


@pytest.mark.parametrize("resource", ["*", "OTHER_TABLE_RESOURCE", [TABLE_RESOURCE, "OTHER"]])
def test_dynamodb_authority_must_target_exact_table(resource: Any) -> None:
    policy = _valid_policy()
    policy["Statement"][0]["Resource"] = resource
    with pytest.raises(IamContractError, match="exact DynamoDB table resource"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


@pytest.mark.parametrize("negative_key", ["NotAction", "NotResource"])
def test_negative_allow_selectors_are_rejected(negative_key: str) -> None:
    policy = _valid_policy()
    statement = policy["Statement"][0]
    if negative_key == "NotAction":
        statement[negative_key] = statement.pop("Action")
    else:
        statement[negative_key] = statement.pop("Resource")
    with pytest.raises(IamContractError, match="negative selectors"):
        validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


def test_direct_actions_cannot_be_conditioned_or_mixed_with_transactional_put() -> None:
    conditioned = _valid_policy()
    conditioned["Statement"][0]["Condition"] = {
        "StringEquals": {"aws:RequestedRegion": "example-region"}
    }
    with pytest.raises(IamContractError, match="conditions required direct"):
        validate_dynamodb_runtime_policy(conditioned, table_resource=TABLE_RESOURCE)

    mixed = _valid_policy()
    mixed["Statement"][0]["Action"].append("dynamodb:PutItem")
    with pytest.raises(IamContractError, match="transaction-only PutItem must be isolated"):
        validate_dynamodb_runtime_policy(mixed, table_resource=TABLE_RESOURCE)


def test_validator_is_not_confused_by_non_dynamodb_allow_statements() -> None:
    policy = deepcopy(_valid_policy())
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "EXACT_LOG_RESOURCE",
        }
    )
    validate_dynamodb_runtime_policy(policy, table_resource=TABLE_RESOURCE)


def test_table_resource_input_itself_must_be_exact() -> None:
    with pytest.raises(IamContractError, match="exact DynamoDB table resource"):
        validate_dynamodb_runtime_policy(_valid_policy(), table_resource="*")
