from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_fork_cloud_authority import (
    EXPECTED_REPOSITORY,
    _verify_trusted_preflight,
    _verify_workflow_text,
    verify_repository,
)


def _reviewed_manual_secret_payload() -> str:
    return """jobs:
  model-smoke:
    if: ${{ inputs.run_model && github.ref == 'refs/heads/main' }}
    environment: credentialed-validation
    steps:
      - name: Require explicit credential
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
      - name: Run bounded live Agent SDK evaluation
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
"""


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("permissions:\n  id-token: write\n", "GitHub OIDC permission"),
        ("permissions: {contents: read, id-token: write}\n", "GitHub OIDC permission"),
        (
            "env:\n  TOKEN_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}\n",
            "GitHub OIDC request environment",
        ),
        (
            "uses: aws-actions/configure-aws-credentials@0123456789012345678901234567890123456789\n",
            "AWS credential action",
        ),
        ("issuer: https://token.actions.githubusercontent.com\n", "GitHub OIDC provider"),
        ("run: aws sts get-caller-identity\n", "AWS STS command"),
        ("env:\n  AWS_ACCESS_KEY_ID: value\n", "AWS access key"),
        ("env:\n  AWS_SECRET_ACCESS_KEY: value\n", "AWS secret key"),
        ("env:\n  AWS_SESSION_TOKEN: value\n", "AWS session token"),
        (
            "with:\n  role-to-assume: arn:aws:iam::123456789012:role/example\n",
            "AWS role-to-assume input",
        ),
        ("on:\n  pull_request_target:\n", "pull_request_target trigger"),
        ("on: [pull_request_target]\n", "pull_request_target trigger"),
        (
            "env:\n  CLOUD_TOKEN: ${{ secrets['CLOUD_TOKEN'] }}\n",
            "indirect GitHub secret reference",
        ),
        (
            "env:\n  CLOUD_TOKEN: ${{ secrets[env.SECRET_NAME] }}\n",
            "indirect GitHub secret reference",
        ),
        ("secrets: inherit\n", "inherited GitHub secrets"),
    ],
)
def test_workflow_cloud_authority_tokens_fail_closed(payload: str, expected: str) -> None:
    with pytest.raises(ValueError, match=expected):
        _verify_workflow_text("ci.yml", payload)


def test_unreviewed_secret_reference_fails_closed() -> None:
    payload = "env:\n  CLOUD_TOKEN: ${{ secrets.UNREVIEWED_CLOUD_TOKEN }}\n"
    with pytest.raises(ValueError, match="secret references differ from reviewed allowlist"):
        _verify_workflow_text("ci.yml", payload)


def test_extra_reviewed_secret_reference_fails_closed() -> None:
    payload = _reviewed_manual_secret_payload() + (
        "      - name: Unreviewed third consumer\n"
        "        env:\n"
        "          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
    )
    with pytest.raises(ValueError, match="secret references differ from reviewed allowlist"):
        _verify_workflow_text("manual-validation.yml", payload)


def test_reviewed_secret_consumer_movement_fails_closed() -> None:
    payload = _reviewed_manual_secret_payload().replace(
        "- name: Require explicit credential",
        "- name: Export credential elsewhere",
        1,
    )
    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("manual-validation.yml", payload)


def test_reviewed_non_aws_secret_consumers_do_not_create_cloud_authority() -> None:
    result = _verify_workflow_text("manual-validation.yml", _reviewed_manual_secret_payload())
    assert result["aws_authentication"] == "forbidden"
    assert result["secrets"] == {"ANTHROPIC_API_KEY": 2}


def test_trusted_preflight_requires_canonical_repository_and_fork_rejection() -> None:
    preflight = (Path(__file__).parents[2] / "scripts" / "auto_trusted_preflight.py").read_text()
    result = _verify_trusted_preflight(preflight)
    assert result == {
        "repository": EXPECTED_REPOSITORY,
        "owner": "portyu9",
        "fork_heads": "rejected",
        "external_actors": "rejected",
    }


def test_trusted_preflight_fails_if_fork_rejection_is_removed() -> None:
    preflight = (Path(__file__).parents[2] / "scripts" / "auto_trusted_preflight.py").read_text()
    mutated = preflight.replace(
        'raise ValueError("fork/external-head workflow runs are not auto-authorized")',
        'raise ValueError("external workflow")',
        1,
    )
    with pytest.raises(ValueError, match="lost canonical repository/fork isolation"):
        _verify_trusted_preflight(mutated)


def test_current_repository_has_no_github_actions_aws_authority() -> None:
    result = verify_repository(Path(__file__).parents[2])
    assert result["canonical_repository"] == EXPECTED_REPOSITORY
    assert result["github_actions_aws_authentication"] == "forbidden"
    assert result["fork_cloud_authority"] == "denied"
    assert result["trusted_preflight"]["fork_heads"] == "rejected"
    assert {row["workflow"] for row in result["workflows"]} == {
        "ci.yml",
        "manual-validation.yml",
        "release-candidate.yml",
        "trusted-pr-auto.yml",
    }
