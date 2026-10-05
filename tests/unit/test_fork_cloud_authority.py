from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_fork_cloud_authority import (
    EXPECTED_REPOSITORY,
    _verify_no_external_gate_dependency,
    _verify_retired_external_trusted_gate,
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


def _reviewed_governance_secret_payload() -> str:
    return """jobs:
  govern:
    if: >-
      github.event_name == 'schedule' ||
      (github.event_name == 'workflow_run' &&
       github.event.workflow_run.head_repository.full_name == github.repository &&
       (github.event.workflow_run.head_branch == 'main' ||
        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||
        startsWith(github.event.workflow_run.head_branch, 'automation/dependency-promotion-')))
    env:
      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}
    steps:
      - name: Recover exact accepted-main dependency validation before mutation
        if: steps.revision.outputs.current == 'true'
        id: post_merge_recovery
        env:
          GITHUB_TOKEN: ${{ github.token }}
      - name: Attempt one bounded transient recovery
        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true' && (github.event_name == 'workflow_run' || github.event_name == 'schedule')
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Mint independent promotion author token
        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true'
        id: promotion-author-app
        with:
          private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}
          permission-contents: write
          permission-pull-requests: write
      - name: Reconcile exact-subject Python dependency promotion
        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true'
        id: python_promotion
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PROMOTION_AUTHOR_TOKEN: ${{ steps.promotion-author-app.outputs.token }}
      - name: Reconcile Dependabot action merge authority
        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true' && steps.python_promotion.outputs.merged != 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
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


def test_reviewed_governance_secret_consumers_do_not_create_aws_authority() -> None:
    result = _verify_workflow_text(
        "dependency-governance.yml", _reviewed_governance_secret_payload()
    )
    assert result["aws_authentication"] == "forbidden"
    assert result["pull_request_target"] == "forbidden"
    assert result["secrets"] == {
        "GITHUB_TOKEN": 3,
        "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 1,
    }


def test_reviewed_governance_secret_consumers_require_control_sha_binding() -> None:
    payload = _reviewed_governance_secret_payload()
    assert "GOVERNANCE_CONTROL_SHA: ${{ github.sha }}" in payload
    mutated = payload.replace(
        "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}\n",
        "",
        1,
    )
    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("dependency-governance.yml", mutated)


def test_reviewed_governance_secret_consumers_require_current_main() -> None:
    payload = _reviewed_governance_secret_payload()
    assert payload.count("steps.revision.outputs.current == 'true'") == 5
    mutated = payload.replace("steps.revision.outputs.current == 'true' && ", "", 1)
    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("dependency-governance.yml", mutated)


def test_reviewed_governance_secret_boundary_rejects_fork_workflow_wake() -> None:
    payload = _reviewed_governance_secret_payload().replace(
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n"
        "        startsWith(github.event.workflow_run.head_branch, "
        "'automation/dependency-promotion-')))",
        "       github.event.workflow_run.head_repository.full_name == github.repository)",
        1,
    )
    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("dependency-governance.yml", payload)


def test_reviewed_governance_secret_consumer_movement_fails_closed() -> None:
    payload = _reviewed_governance_secret_payload().replace(
        "- name: Reconcile exact-subject Python dependency promotion",
        "- name: Export governance token elsewhere",
        1,
    )
    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("dependency-governance.yml", payload)


@pytest.mark.parametrize("trigger", ("pull_request", "workflow_dispatch", "repository_dispatch"))
def test_reviewed_governance_rejects_candidate_manual_or_external_mutation_triggers(
    trigger: str,
) -> None:
    payload = f"on:\n  {trigger}:\n" + _reviewed_governance_secret_payload()
    with pytest.raises(
        ValueError,
        match="must remain accepted-main-only and reject candidate/manual mutation triggers",
    ):
        _verify_workflow_text("dependency-governance.yml", payload)


def test_dependency_governance_pr_workflow_is_secret_free_candidate_evidence() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "dependency-governance-pr.yml").read_text(
        encoding="utf-8"
    )
    result = _verify_workflow_text("dependency-governance-pr.yml", workflow)
    assert result["secrets"] == {}
    assert result["pull_request_target"] == "forbidden"


@pytest.mark.parametrize(
    "injected",
    (
        "  workflow_run:\n",
        "  status:\n",
        "  schedule:\n",
        "  environment: candidate-secret\n",
        "  contents: write\n",
        "  pull-requests: write\n",
    ),
)
def test_dependency_governance_pr_rejects_authority_expansion(injected: str) -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "dependency-governance-pr.yml").read_text(
        encoding="utf-8"
    )
    mutated = workflow.replace("on:\n", f"on:\n{injected}", 1)
    with pytest.raises(
        ValueError,
        match="must remain read-only candidate development evidence",
    ):
        _verify_workflow_text("dependency-governance-pr.yml", mutated)


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
        'head_repository.get("full_name") != EXPECTED_REPOSITORY',
        'head_repository.get("full_name") != "attacker/fork"',
        1,
    )
    with pytest.raises(ValueError, match="lost canonical repository/fork isolation"):
        _verify_trusted_preflight(mutated)


def test_trusted_preflight_rejects_retired_direct_owner_comment_wake_constants() -> None:
    preflight = (Path(__file__).parents[2] / "scripts" / "auto_trusted_preflight.py").read_text()
    mutated = preflight + '\nEXPECTED_MAINTENANCE_WAKE_WORKFLOW_NAME = "retired"\n'

    with pytest.raises(
        ValueError, match="reintroduced retired direct owner-comment wake authority"
    ):
        _verify_trusted_preflight(mutated)


@pytest.mark.parametrize(
    "fragment",
    (
        'actor.get("login") == EXPECTED_OWNER',
        'actor.get("id") == EXPECTED_OWNER_ID',
        'triggering_actor.get("login") == EXPECTED_OWNER',
        'triggering_actor.get("id") == EXPECTED_OWNER_ID',
    ),
)
def test_trusted_preflight_fails_if_reviewed_owner_ci_identity_exactness_is_removed(
    fragment: str,
) -> None:
    preflight = (Path(__file__).parents[2] / "scripts" / "auto_trusted_preflight.py").read_text()
    assert fragment in preflight
    mutated = preflight.replace(fragment, fragment.replace(" == ", " != "), 1)
    with pytest.raises(ValueError, match="lost canonical repository/fork isolation"):
        _verify_trusted_preflight(mutated)


def test_retired_trusted_maintenance_wake_is_absent() -> None:
    root = Path(__file__).parents[2]
    assert not (root / ".github" / "workflows" / "trusted-maintenance-wake.yml").exists()


def test_trusted_auto_secret_is_isolated_to_exact_trusted_gate_reporter() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "trusted-pr-auto.yml").read_text(encoding="utf-8")

    result = _verify_workflow_text("trusted-pr-auto.yml", workflow)

    assert result["secrets"] == {"TRUSTED_GATE_APP_PRIVATE_KEY": 1}
    assert result["pull_request_target"] == "forbidden"


@pytest.mark.parametrize("trigger", ("workflow_dispatch", "repository_dispatch", "issue_comment"))
def test_trusted_auto_rejects_candidate_ref_or_external_authority(trigger: str) -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "trusted-pr-auto.yml").read_text(encoding="utf-8")
    marker = '  schedule:\n    - cron: "*/5 * * * *"\n'
    assert marker in workflow
    mutated = workflow.replace(marker, marker + f"  {trigger}:\n", 1)

    with pytest.raises(ValueError, match="candidate-ref or external authority triggers"):
        _verify_workflow_text("trusted-pr-auto.yml", mutated)


def test_trusted_auto_rejects_private_key_consumer_movement() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "trusted-pr-auto.yml").read_text(encoding="utf-8")
    mutated = workflow.replace(
        "- name: Mint dedicated Trusted PR Gate token",
        "- name: Export Trusted Gate private key elsewhere",
        1,
    )

    with pytest.raises(ValueError, match="reviewed trusted-gate credential boundary"):
        _verify_workflow_text("trusted-pr-auto.yml", mutated)


def test_retired_external_trusted_gate_runtime_cannot_return(tmp_path: Path) -> None:
    (tmp_path / "scripts" / "trusted_gate_service").mkdir(parents=True)

    with pytest.raises(ValueError, match="retired external trusted-gate runtime reintroduced"):
        _verify_retired_external_trusted_gate(tmp_path)


@pytest.mark.parametrize(
    "payload",
    (
        "import boto3\n",
        "TRUSTED_GATE_CONFIG_PREFIX=x\n",
        "endpoint=/github/webhook\n",
        "host=retired.example." + "amazonaws.com\n",
        "X-GitHub-Delivery: replay-id\n",
    ),
)
def test_trusted_control_rejects_external_gate_dependency(payload: str) -> None:
    with pytest.raises(ValueError, match="external trusted-gate dependency"):
        _verify_no_external_gate_dependency("trusted control", payload)


def test_current_repository_has_no_github_actions_aws_authority() -> None:
    result = verify_repository(Path(__file__).parents[2])
    assert result["canonical_repository"] == EXPECTED_REPOSITORY
    assert result["github_actions_aws_authentication"] == "forbidden"
    assert result["external_trusted_gate_runtime"] == "retired"
    assert result["external_trusted_gate_dependency"] == "forbidden"
    assert result["fork_cloud_authority"] == "denied"
    assert result["trusted_preflight"]["fork_heads"] == "rejected"
    assert {row["workflow"] for row in result["workflows"]} == {
        "ci.yml",
        "codeql.yml",
        "dependency-governance-pr.yml",
        "dependency-governance.yml",
        "dependency-trusted-merge.yml",
        "manual-validation.yml",
        "post-merge-ci.yml",
        "protected-security-remediation.yml",
        "release-candidate.yml",
        "ruleset-drift-sentinel.yml",
        "ruleset-reconciler.yml",
        "security-autoheal-pr.yml",
        "security-autoheal.yml",
        "trusted-pr-auto.yml",
    }


def test_dependency_trusted_merge_owner_review_secret_is_isolated() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "dependency-trusted-merge.yml").read_text(
        encoding="utf-8"
    )
    result = _verify_workflow_text("dependency-trusted-merge.yml", workflow)
    assert result["secrets"] == {"PORTYU9_BOT_REVIEW_TOKEN": 1}
    assert result["pull_request_target"] == "forbidden"

    approve_start = workflow.index("  approve:\n")
    merge_start = workflow.index("\n  merge:\n", approve_start)
    approve = workflow[approve_start:merge_start]
    secret = "          PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}\n"
    assert secret in approve
    mutated_approve = approve.replace(secret, "", 1)
    merge = workflow[merge_start:]
    env_marker = "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}\n"
    assert env_marker in merge
    mutated_merge = merge.replace(
        env_marker,
        env_marker + "      PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}\n",
        1,
    )
    mutated = workflow[:approve_start] + mutated_approve + mutated_merge
    with pytest.raises(
        ValueError,
        match="reviewed one-way merge authority changed",
    ):
        _verify_workflow_text("dependency-trusted-merge.yml", mutated)


def test_post_merge_ci_has_no_cloud_or_merge_authority() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "post-merge-ci.yml").read_text(encoding="utf-8")
    result = _verify_workflow_text("post-merge-ci.yml", workflow)
    assert result["secrets"] == {}
    assert result["pull_request_target"] == "forbidden"

    elevated = workflow.replace(
        "permissions:\n  contents: read",
        "permissions:\n  contents: write",
        1,
    )
    with pytest.raises(
        ValueError,
        match="must remain dispatch-free accepted-main validation",
    ):
        _verify_workflow_text("post-merge-ci.yml", elevated)

    expanded_checks = workflow.replace(
        "permissions:\n  contents: read",
        "permissions:\n  contents: read\n  checks: write",
        1,
    )
    with pytest.raises(
        ValueError,
        match="must isolate exactly two canonical reusable-call checks write ceilings",
    ):
        _verify_workflow_text("post-merge-ci.yml", expanded_checks)

    duplicated_sarif = workflow.replace(
        "permissions:\n  contents: read",
        "permissions:\n  contents: read\n  security-events: write",
        1,
    )
    with pytest.raises(
        ValueError,
        match="must isolate exactly one CodeQL SARIF write authority",
    ):
        _verify_workflow_text("post-merge-ci.yml", duplicated_sarif)


def test_post_merge_ci_rejects_repository_dispatch_reintroduction() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "post-merge-ci.yml").read_text(encoding="utf-8")
    marker = "    types: [completed]\n"
    assert marker in workflow
    mutated = workflow.replace(
        marker,
        marker + "  repository_dispatch:\n    types: [governed-post-merge-validation]\n",
        1,
    )

    with pytest.raises(
        ValueError,
        match="must remain dispatch-free accepted-main validation",
    ):
        _verify_workflow_text("post-merge-ci.yml", mutated)


def test_post_merge_ci_rejects_dependency_trusted_merge_wake() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "post-merge-ci.yml").read_text(encoding="utf-8")
    reviewed = (
        "workflows: [dependency-governance, Security Auto-Heal, "
        "Protected Security Remediation — ƳƤ AI QA Automation Framework]"
    )
    assert reviewed in workflow
    mutated = workflow.replace(
        reviewed,
        "workflows: [dependency-governance, Dependency Trusted Merge — ƳƤ AI QA Automation Framework, "
        "Security Auto-Heal, Protected Security Remediation — ƳƤ AI QA Automation Framework]",
        1,
    )

    with pytest.raises(
        ValueError,
        match="reviewed accepted-main validation boundary changed",
    ):
        _verify_workflow_text("post-merge-ci.yml", mutated)


def test_post_merge_ci_requires_unrelated_stale_wake_boundary() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "post-merge-ci.yml").read_text(encoding="utf-8")
    reviewed = "unrelated_main_merge_re='^Merge pull request #[1-9][0-9]* from [A-Za-z0-9_.-]+/'"
    assert reviewed in workflow
    mutated = workflow.replace(
        reviewed,
        "unrelated_main_merge_re='^Merge pull request #[1-9][0-9]* from portyu9/automation/codeql-autoheal-'",
        1,
    )

    with pytest.raises(ValueError, match="reviewed accepted-main validation boundary changed"):
        _verify_workflow_text("post-merge-ci.yml", mutated)


def test_security_autoheal_pr_workflow_is_read_only_candidate_evidence() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "security-autoheal-pr.yml").read_text(
        encoding="utf-8"
    )
    result = _verify_workflow_text("security-autoheal-pr.yml", workflow)
    assert result["secrets"] == {}
    assert result["pull_request_target"] == "forbidden"


@pytest.mark.parametrize(
    "injected",
    (
        "  workflow_run:\n",
        "  schedule:\n",
        "  workflow_dispatch:\n",
        "  contents: write\n",
        "  pull-requests: write\n",
        "  security-events: write\n",
    ),
)
def test_security_autoheal_pr_rejects_authority_expansion(injected: str) -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "security-autoheal-pr.yml").read_text(
        encoding="utf-8"
    )
    mutated = workflow.replace("on:\n", f"on:\n{injected}", 1)
    with pytest.raises(
        ValueError,
        match="must remain read-only candidate development evidence",
    ):
        _verify_workflow_text("security-autoheal-pr.yml", mutated)


def test_security_autoheal_privileged_controller_rejects_pull_request_execution() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "security-autoheal.yml").read_text(
        encoding="utf-8"
    )
    mutated = workflow.replace("on:\n", "on:\n  pull_request:\n", 1)
    with pytest.raises(ValueError, match="must remain accepted-main-only"):
        _verify_workflow_text("security-autoheal.yml", mutated)


@pytest.mark.parametrize(
    ("guarded_fragment", "unguarded_fragment"),
    (
        (
            "- name: Plan exact-main deterministic security routes\n"
            "        if: steps.revision.outputs.current == 'true'\n"
            "        env:",
            "- name: Plan exact-main deterministic security routes\n        env:",
        ),
        (
            "- name: Persist exact-run route plan before mutation\n"
            "        if: steps.revision.outputs.current == 'true'\n"
            "        id: route-plan-artifact",
            "- name: Persist exact-run route plan before mutation\n        id: route-plan-artifact",
        ),
    ),
)
def test_security_autoheal_requires_current_main_guards_on_route_evidence(
    guarded_fragment: str,
    unguarded_fragment: str,
) -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "security-autoheal.yml").read_text(
        encoding="utf-8"
    )
    assert guarded_fragment in workflow
    mutated = workflow.replace(guarded_fragment, unguarded_fragment, 1)

    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("security-autoheal.yml", mutated)


def test_security_autoheal_author_secret_requires_protected_environment() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "security-autoheal.yml").read_text(
        encoding="utf-8"
    )
    reviewed = "environment:\n      name: protected-remediation-author\n      deployment: false"
    assert reviewed in workflow
    mutated = workflow.replace(
        reviewed,
        "environment:\n      name: unreviewed-security-author\n      deployment: false",
        1,
    )

    with pytest.raises(ValueError, match="reviewed credential consumers moved or changed"):
        _verify_workflow_text("security-autoheal.yml", mutated)


def test_protected_remediation_author_secret_is_trusted_wake_only() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "protected-security-remediation.yml").read_text(
        encoding="utf-8"
    )

    result = _verify_workflow_text("protected-security-remediation.yml", workflow)

    assert result["secrets"] == {
        "PORTYU9_BOT_REVIEW_TOKEN": 1,
        "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 2,
    }
    assert result["pull_request_target"] == "forbidden"


def test_protected_remediation_author_secret_rejects_pull_request_execution() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "protected-security-remediation.yml").read_text(
        encoding="utf-8"
    )
    mutated = workflow.replace(
        "on:\n  workflow_run:\n",
        "on:\n  pull_request:\n  workflow_run:\n",
        1,
    )

    with pytest.raises(ValueError, match="default-branch trusted-wake-only"):
        _verify_workflow_text("protected-security-remediation.yml", mutated)


def test_protected_remediation_author_secret_rejects_unbound_workflow_run() -> None:
    root = Path(__file__).parents[2]
    workflow = (root / ".github" / "workflows" / "protected-security-remediation.yml").read_text(
        encoding="utf-8"
    )
    marker = "       github.event.workflow_run.head_sha == github.sha)\n"
    assert marker in workflow
    mutated = workflow.replace(marker, "       github.event.workflow_run.head_sha != '')\n", 1)

    with pytest.raises(ValueError, match="reviewed author credential boundary changed"):
        _verify_workflow_text("protected-security-remediation.yml", mutated)
