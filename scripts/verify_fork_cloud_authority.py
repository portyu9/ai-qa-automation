from __future__ import annotations

import argparse
import ast
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_OWNER = "portyu9"
EXPECTED_WORKFLOW_NAMES = {
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
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_WORKFLOW_ENTRIES = 16
MAX_PREFLIGHT_BYTES = 64 * 1024

# The production control plane is GitHub-native. Workflows must never acquire AWS/cloud
# credentials, and the retired external trusted-gate runtime must not return.
_FORBIDDEN_WORKFLOW_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub OIDC permission", re.compile(r"(?i)\bid-token\s*:")),
    (
        "GitHub OIDC request environment",
        re.compile(r"(?i)ACTIONS_ID_TOKEN_REQUEST_(?:URL|TOKEN)"),
    ),
    ("AWS credential action", re.compile(r"(?i)\baws-actions/")),
    ("GitHub OIDC provider", re.compile(r"(?i)token\.actions\.githubusercontent\.com")),
    ("AWS web-identity assumption", re.compile(r"(?i)assumerolewithwebidentity")),
    ("AWS role-to-assume input", re.compile(r"(?i)role-to-assume")),
    ("AWS web identity token file", re.compile(r"(?i)aws_web_identity_token_file")),
    ("AWS access key", re.compile(r"(?i)aws_access_key_id")),
    ("AWS secret key", re.compile(r"(?i)aws_secret_access_key")),
    ("AWS session token", re.compile(r"(?i)aws_session_token")),
    ("AWS shared credentials file", re.compile(r"(?i)aws_shared_credentials_file")),
    ("AWS profile", re.compile(r"(?i)aws_(?:default_)?profile")),
    ("AWS credential file", re.compile(r"(?i)(?:~|\$HOME)/\.aws/credentials")),
    (
        "AWS credential process",
        re.compile(r"(?i)credential_process|credential_source|source_profile"),
    ),
    ("AWS configure command", re.compile(r"(?i)\baws\s+configure\b")),
    ("AWS STS command", re.compile(r"(?i)\baws\s+sts\b")),
    ("AWS-prefixed GitHub secret", re.compile(r"(?i)secrets\.AWS[_A-Z0-9]*")),
    (
        "retired external trusted-gate dependency",
        re.compile(
            r"(?i)trusted_gate_service|TRUSTED_GATE_(?:CONFIG_PREFIX|TABLE_NAME|POLICY_SHA256)|"
            r"amazonaws\.com|/github/webhook"
        ),
    ),
    ("indirect GitHub secret reference", re.compile(r"(?i)\bsecrets\s*\[")),
    ("inherited GitHub secrets", re.compile(r"(?i)\bsecrets\s*:\s*inherit\b")),
    ("pull_request_target trigger", re.compile(r"(?i)\bpull_request_target\b")),
)

_ALLOWED_SECRET_REFERENCE_COUNTS: dict[str, Counter[str]] = {
    "dependency-governance.yml": Counter(
        {"GITHUB_TOKEN": 3, "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 1}
    ),
    "dependency-trusted-merge.yml": Counter({"PORTYU9_BOT_REVIEW_TOKEN": 1}),
    "manual-validation.yml": Counter({"ANTHROPIC_API_KEY": 2}),
    "protected-security-remediation.yml": Counter(
        {"PORTYU9_BOT_REVIEW_TOKEN": 1, "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 2}
    ),
    "ruleset-reconciler.yml": Counter(
        {
            "PORTYU9_RULESET_ADMIN_APP_ID": 1,
            "PORTYU9_RULESET_ADMIN_INSTALLATION_ID": 1,
            "PORTYU9_RULESET_ADMIN_PRIVATE_KEY": 1,
        }
    ),
    "security-autoheal.yml": Counter(
        {"PORTYU9_BOT_REVIEW_TOKEN": 1, "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 1}
    ),
    "trusted-pr-auto.yml": Counter({"TRUSTED_GATE_APP_PRIVATE_KEY": 1}),
}
_SECRET_REFERENCE_RE = re.compile(r"\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_MANUAL_SECRET_CONTEXT_FRAGMENTS = (
    "environment: credentialed-validation",
    "if: ${{ inputs.run_model && github.ref == 'refs/heads/main' }}",
    "- name: Require explicit credential\n        env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}",
    "- name: Run bounded live Agent SDK evaluation\n        env:\n          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}",
)
_GOVERNANCE_SECRET_CONTEXT_FRAGMENTS = (
    "env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}",
    "if: >-\n      github.event_name == 'schedule' ||\n      (github.event_name == 'workflow_run' &&\n       github.event.workflow_run.head_repository.full_name == github.repository &&\n       (github.event.workflow_run.head_branch == 'main' ||\n        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n        startsWith(github.event.workflow_run.head_branch, 'automation/dependency-promotion-')))",
    "- name: Recover exact accepted-main dependency validation before mutation\n        if: steps.revision.outputs.current == 'true'\n        id: post_merge_recovery\n        env:\n          GITHUB_TOKEN: ${{ github.token }}",
    "- name: Attempt one bounded transient recovery\n        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true' && (github.event_name == 'workflow_run' || github.event_name == 'schedule')\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
    "- name: Mint independent promotion author token\n        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true'\n        id: promotion-author-app",
    "private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
    "permission-contents: write",
    "permission-pull-requests: write",
    "- name: Reconcile exact-subject Python dependency promotion\n        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true'\n        id: python_promotion\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          PROMOTION_AUTHOR_TOKEN: ${{ steps.promotion-author-app.outputs.token }}",
    "- name: Reconcile Dependabot action merge authority\n        if: steps.revision.outputs.current == 'true' && steps.post_merge_recovery.outputs.mutation_ready == 'true' && steps.python_promotion.outputs.merged != 'true'\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
)
_DEPENDENCY_TRUSTED_MERGE_AUTHORITY_FRAGMENTS = (
    "on:\n  workflow_run:\n    workflows: [\"Trusted PR Auto Gate — ƳƤ AI QA Automation Framework\"]\n    types: [completed]",
    "permissions:\n  contents: read",
    "group: dependency-trusted-merge-global-reconcile",
    "name: Resolve exact trusted dependency subject",
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.head_repository.full_name == github.repository",
    "github.event.workflow_run.head_sha == github.sha",
    "name: Approve exact trusted dependency subject as portyu9",
    "environment:\n      name: portyu9-review-identity\n      deployment: false",
    "PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
    "name: Merge exact trusted dependency subject",
    "environment:\n      name: protected-remediation-author\n      deployment: false",
    "permissions:\n      actions: read\n      contents: write\n      pull-requests: write\n      statuses: read",
    "--target-promotion-pr \"${{ needs.resolve.outputs.pr_number }}\"",
    "--target-dependabot-pr \"${{ needs.resolve.outputs.pr_number }}\"",
    "outputs:\n      control_sha: ${{ steps.post_merge_subject.outputs.control_sha }}\n      subject_sha: ${{ steps.post_merge_subject.outputs.subject_sha }}",
    "name: Bind exact accepted-main post-merge validation subject",
    " subject_sha=\"$(gh api \"repos/${GITHUB_REPOSITORY}/branches/main\" --jq .commit.sha)\"",
    ".parents[0].sha == $control",
    ".parents[1].sha == $head",
    "name: Delete consumed dependency promotion branch",
    "permissions:\n      contents: write\n      pull-requests: read",
    "--cleanup-merged-promotion",
    "--expected-control-sha \"${{ needs.merge.outputs.control_sha }}\"",
    "--expected-subject-sha \"${{ needs.merge.outputs.subject_sha }}\"",
    "name: Validate exact merged dependency CI",
    "uses: ./.github/workflows/ci.yml",
    "subject_sha: ${{ needs.merge.outputs.subject_sha }}",
    "name: Validate exact merged dependency CodeQL",
    "security-events: write",
    "uses: ./.github/workflows/codeql.yml",
    "name: Dependency Post-Merge Required Gate",
    "test \"$GITHUB_RUN_ATTEMPT\" = \"1\"",
    "Dependency Post-Merge Gate",
    "aiqa-dependency-post-merge-v1:",
    ".app.id == 15368",
    ".app.slug == \"github-actions\"",
)
_PROTECTED_REMEDIATION_SECRET_CONTEXT_FRAGMENTS = (
    'on:\n  workflow_run:\n    workflows: ["Security Auto-Heal"]\n    types: [completed]\n  schedule:\n    - cron: "*/5 * * * *"',
    "if: >-\n      github.event_name == 'schedule' ||\n      (github.event_name == 'workflow_run' &&\n       github.event.workflow_run.conclusion == 'success' &&\n       github.event.workflow_run.head_repository.full_name == github.repository &&\n       github.event.workflow_run.head_sha == github.sha)",
    "env:\n      PROTECTED_REMEDIATION_CONTROL_SHA: ${{ github.sha }}",
    "environment:\n      name: protected-remediation-author\n      deployment: false",
    "- name: Verify current trusted protected-remediation control revision\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: >-\n          python .github/scripts/protected_security_remediation.py\n          --validate-control-revision",
    "- name: Mint dedicated protected-remediation author token",
    "private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
    "permission-contents: write",
    "permission-pull-requests: write",
    "python .github/scripts/protected_security_remediation.py --reconcile",
    "environment:\n      name: portyu9-review-identity\n      deployment: false",
    "PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
    "python .github/scripts/protected_security_remediation.py\n          --approve-owner-review",
    "- name: Mint dedicated protected-remediation merge token",
    "PROTECTED_REMEDIATION_APP_TOKEN: ${{ steps.merge-author-app.outputs.token }}",
    '--merge-approved-pr "${{ needs.approve.outputs.pr_number }}"',
)

_POST_MERGE_CI_AUTHORITY_FRAGMENTS = (
    "on:\n  workflow_run:\n    workflows: [dependency-governance, Security Auto-Heal, Protected Security Remediation — ƳƤ AI QA Automation Framework]\n    types: [completed]",
    "case \"$UPSTREAM_NAME:$UPSTREAM_PATH\" in",
    "\"dependency-governance:.github/workflows/dependency-governance.yml\")",
    "\"Security Auto-Heal:.github/workflows/security-autoheal.yml\")",
    "\"Protected Security Remediation — ƳƤ AI QA Automation Framework:.github/workflows/protected-security-remediation.yml\")",
    "merge_author_login='github-actions[bot]'",
    "merge_author_id=41898282",
    "merge_author_login='portyu9-security-remediator[bot]'",
    "merge_author_id=333833782",
    "unrelated_main_merge_re='^Merge pull request #[1-9][0-9]* from [A-Za-z0-9_.-]+'",
    ".author.login == $merge_author_login",
    ".author.id == $merge_author_id",
    "permissions:\n  contents: read",
    "test \"$UPSTREAM_REPOSITORY\" = \"$GITHUB_REPOSITORY\"",
    "test \"$UPSTREAM_HEAD_REPOSITORY\" = \"$GITHUB_REPOSITORY\"",
    "test \"$live_main\" = \"$SUBJECT_SHA\"",
    "permissions:\n      checks: write\n      contents: read\n    uses: ./.github/workflows/ci.yml",
    "permissions:\n      actions: read\n      checks: write\n      contents: read\n      security-events: write\n    uses: ./.github/workflows/codeql.yml",
)
_SECURITY_AUTOHEAL_SECRET_CONTEXT_FRAGMENTS = (
    "if: >-\n      github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch' ||\n      (github.event_name == 'workflow_run' &&\n       github.event.workflow_run.conclusion == 'success' &&\n       github.event.workflow_run.head_repository.full_name == github.repository &&\n       (github.event.workflow_run.head_branch == 'main' ||\n        github.event.workflow_run.name == 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'))",
    "- name: Plan exact-main deterministic security routes\n        if: steps.revision.outputs.current == 'true'\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: >-\n          python .github/scripts/security_autoheal.py\n          --plan-routes",
    "- name: Persist exact-run route plan before mutation\n        if: steps.revision.outputs.current == 'true'\n        id: route-plan-artifact\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
    '- name: Require accepted-main dependency validation before security mutation\n        id: post_merge_barrier\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: >-\n          python .github/scripts/dependency_recovery.py\n          --check-post-merge\n          --github-output "$GITHUB_OUTPUT"',
    "environment:\n      name: protected-remediation-author\n      deployment: false",
    "- name: Validate independent security repair publisher identity configuration\n        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'",
    "- name: Mint independent security repair publisher token\n        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'\n        id: repair-author-app",
    "private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
    "permission-pull-requests: write",
    "- name: Bind security repair publisher token to reviewed bot identity\n        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'",
    "- name: Restore exact-run route plan from prior read-only job\n        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'\n        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8",
    "- name: Reconcile exact-subject CodeQL remediations from persisted routes\n        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n          SECURITY_AUTOHEAL_AUTHOR_TOKEN: ${{ steps.repair-author-app.outputs.token }}\n          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}\n          PROTECTED_REMEDIATION_BOT_ID: ${{ vars.PROTECTED_REMEDIATION_BOT_ID }}\n        run: >-\n          python .github/scripts/security_autoheal.py\n          --reconcile\n          --route-plan \"$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json\"",
    "environment:\n      name: portyu9-review-identity\n      deployment: false",
    "PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
    "python .github/scripts/security_autoheal.py\n          --approve-owner-review",
    '--merge-approved-pr "${{ needs.approve.outputs.pr_number }}"',
)


_RULESET_RECONCILER_SECRET_CONTEXT_FRAGMENTS = (
    "environment: ruleset-admin-identity",
    "if: ${{ needs.plan.outputs.live_state == 'predecessor' }}",
    "ADMIN_APP_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_APP_ID }}",
    "ADMIN_INSTALLATION_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_INSTALLATION_ID }}",
    "ADMIN_PRIVATE_KEY: ${{ secrets.PORTYU9_RULESET_ADMIN_PRIVATE_KEY }}",
    "permissions[administration]=write",
    "repos/portyu9/ai-qa-automation/rulesets/21201916",
    "python3 scripts/ruleset_transition_contract.py require-successor",
)

_RULESET_SENTINEL_READ_ONLY_FRAGMENTS = (
    "permissions:\n  contents: read",
    "group: ruleset-drift-sentinel",
    "GITHUB_TOKEN: ${{ github.token }}",
    'GH_TOKEN="$GITHUB_TOKEN" gh api repos/portyu9/ai-qa-automation/rulesets/21201916',
    "python3 scripts/ruleset_transition_contract.py require-witnessed-successor",
    "--witness .github/rulesets/ruleset-drift-witness-v1.json",
)


_TRUSTED_AUTO_SECRET_CONTEXT_FRAGMENTS = (
    'schedule:\n    - cron: "*/5 * * * *"',
    'workflows: ["CI — ƳƤ AI QA Automation Framework", "CodeQL", "dependency-governance", "Security Auto-Heal"]',
    "environment:\n      name: trusted-pr-gate\n      deployment: false",
    "- name: Mint dedicated Trusted PR Gate token",
    "TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
    "if: ${{ needs.preflight.outputs.lane != 'owner-routine' && needs.preflight.outputs.lane != 'owner-protected-maintenance' }}",
)

_REQUIRED_PREFLIGHT_FRAGMENTS = (
    f'EXPECTED_REPOSITORY = "{EXPECTED_REPOSITORY}"',
    f'EXPECTED_OWNER = "{EXPECTED_OWNER}"',
    "if repository != EXPECTED_REPOSITORY:",
    'repository.get("full_name") != EXPECTED_REPOSITORY',
    'head_repository.get("full_name") != EXPECTED_REPOSITORY',
    'actor.get("login") == EXPECTED_OWNER',
    'actor.get("id") == EXPECTED_OWNER_ID',
    'triggering_actor.get("login") == EXPECTED_OWNER',
    'triggering_actor.get("id") == EXPECTED_OWNER_ID',
    'kind="owner-ci"',
    'head_repo.get("full_name") == EXPECTED_REPOSITORY',
    'base_repo.get("full_name") == EXPECTED_REPOSITORY',
    'PROTECTED_REMEDIATION_BOT_LOGIN_ENV = "PROTECTED_REMEDIATION_BOT_LOGIN"',
    'PROTECTED_REMEDIATION_BOT_ID_ENV = "PROTECTED_REMEDIATION_BOT_ID"',
    'return "protected-security-remediation"',
    'PROTECTED_OWNER_LANE = "owner-protected-maintenance"',
    'PROTECTED_OWNER_REASON = "protected-control-plane-maintenance"',
    "PROTECTED_OWNER_COMMAND_RE = re.compile(",
    'api.get(f"/repos/{EXPECTED_REPOSITORY}/issues/comments/{comment_id}")',
    'live_comment.get("body") != body',
    'live_comment.get("created_at")',
    'live_comment.get("updated_at")',
    "created_at != updated_at",
    'comment.get("updated_at") != created_at',
    'os.environ.get("GITHUB_REF", "") != f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"',
    'os.environ.get("GITHUB_SHA", "") != trusted_sha',
    'os.environ.get("GITHUB_RUN_ATTEMPT", "") != "1"',
    'os.environ.get("GITHUB_WORKFLOW_REF", "") != expected_workflow_ref',
    'f"/repos/{EXPECTED_REPOSITORY}/pulls?state=open&base={EXPECTED_DEFAULT_BRANCH}"',
    'live_user.get("login") != EXPECTED_OWNER',
    'live_user.get("id") != EXPECTED_OWNER_ID',
    'head_repo.get("full_name") != EXPECTED_REPOSITORY',
    'base_repo.get("full_name") != EXPECTED_REPOSITORY',
    'base.get("sha") != trusted_sha',
    'f"/repos/{EXPECTED_REPOSITORY}/issues/{number}/comments"',
    'user.get("login") != EXPECTED_OWNER',
    'user.get("id") != EXPECTED_OWNER_ID',
    'user.get("type") != "User"',
    'match.group("head") != head_sha or match.group("base") != trusted_sha',
    'match.group("merge") != current_merge_sha',
    "if not admission.protected_changes:",
    "protected_owner = _select_protected_owner_admission(",
    "if protected_owner is not None:",
)


def _read_regular_text(path: Path, *, max_bytes: int, label: str) -> str:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise RuntimeError("fork/cloud authority verification requires O_NOFOLLOW")
    try:
        fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise ValueError(f"{label} cannot be opened as a regular non-symlink file") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise ValueError(f"{label} must be a bounded regular file")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ValueError(f"{label} exceeds the bounded ingestion limit")
        after = os.fstat(fd)
        before_sig = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_sig = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_sig != after_sig:
            raise ValueError(f"{label} changed during ingestion")
    finally:
        os.close(fd)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be UTF-8 text") from exc


def _verify_workflow_text(name: str, text: str) -> dict[str, Any]:
    violations = [label for label, pattern in _FORBIDDEN_WORKFLOW_TOKENS if pattern.search(text)]
    if violations:
        raise ValueError(f"{name}: forbidden cloud/fork authority tokens: {', '.join(violations)}")

    secret_references = Counter(_SECRET_REFERENCE_RE.findall(text))
    allowed_secrets = _ALLOWED_SECRET_REFERENCE_COUNTS.get(name, Counter())
    if secret_references != allowed_secrets:
        raise ValueError(
            f"{name}: secret references differ from reviewed allowlist: "
            f"expected {dict(sorted(allowed_secrets.items()))}, "
            f"got {dict(sorted(secret_references.items()))}"
        )
    if name == "manual-validation.yml":
        missing = [
            fragment for fragment in _MANUAL_SECRET_CONTEXT_FRAGMENTS if fragment not in text
        ]
        if missing:
            raise ValueError(
                "manual-validation.yml: reviewed credential consumers moved or changed"
            )
    if name == "dependency-governance-pr.yml" and any(
        token in text
        for token in (
            "workflow_run:",
            "status:",
            "schedule:",
            "workflow_dispatch:",
            "repository_dispatch:",
            "environment:",
            "${{ vars.",
            "contents: write",
            "pull-requests: write",
            "checks: write",
            "statuses: write",
            "actions: write",
        )
    ):
        raise ValueError(
            "dependency-governance-pr.yml must remain read-only candidate development evidence"
        )
    if name == "dependency-governance.yml":
        if (
            "pull_request:" in text
            or "workflow_dispatch:" in text
            or "repository_dispatch:" in text
        ):
            raise ValueError(
                "dependency-governance.yml must remain accepted-main-only and reject candidate/manual mutation triggers"
            )
        missing = [
            fragment for fragment in _GOVERNANCE_SECRET_CONTEXT_FRAGMENTS if fragment not in text
        ]
        if missing:
            raise ValueError(
                "dependency-governance.yml: reviewed credential consumers moved or changed"
            )
    if name == "dependency-trusted-merge.yml":
        if any(
            token in text
            for token in (
                "pull_request:",
                "pull_request_target:",
                "push:",
                "schedule:",
                "status:",
                "issue_comment:",
                "workflow_dispatch:",
                "repository_dispatch:",
                "actions: write",
                "statuses: write",
                "id-token: write",
                "packages: write",
                "actions/create-github-app-token",
            )
        ):
            raise ValueError(
                "dependency-trusted-merge.yml must remain one-way and same-run certifying only"
            )
        if text.count("contents: write") != 2 or text.count("pull-requests: write") != 1:
            raise ValueError(
                "dependency-trusted-merge.yml must isolate merge plus exact-ref cleanup writes"
            )
        if text.count("checks: write") != 2 or text.count("security-events: write") != 1:
            raise ValueError(
                "dependency-trusted-merge.yml same-run CI/CodeQL/check authority drifted"
            )
        missing = [
            fragment
            for fragment in _DEPENDENCY_TRUSTED_MERGE_AUTHORITY_FRAGMENTS
            if fragment not in text
        ]
        if missing:
            raise ValueError(
                "dependency-trusted-merge.yml reviewed one-way merge authority changed"
            )
    if name == "post-merge-ci.yml":
        if any(
            token in text
            for token in (
                "pull_request:",
                "schedule:",
                "workflow_dispatch:",
                "repository_dispatch:",
                "environment:",
                "${{ vars.",
                "contents: write",
                "actions: write",
                "statuses: write",
                "pull-requests: write",
            )
        ):
            raise ValueError(
                "post-merge-ci.yml must remain dispatch-free accepted-main validation"
            )
        if text.count("checks: write") != 2:
            raise ValueError(
                "post-merge-ci.yml must isolate exactly two canonical reusable-call checks write ceilings"
            )
        if text.count("security-events: write") != 1:
            raise ValueError(
                "post-merge-ci.yml must isolate exactly one CodeQL SARIF write authority"
            )
        missing = [
            fragment for fragment in _POST_MERGE_CI_AUTHORITY_FRAGMENTS if fragment not in text
        ]
        if missing:
            raise ValueError("post-merge-ci.yml reviewed accepted-main validation boundary changed")
    if name == "protected-security-remediation.yml":
        if (
            "pull_request:" in text
            or "workflow_dispatch:" in text
            or "repository_dispatch:" in text
        ):
            raise ValueError(
                "protected-security-remediation.yml must remain default-branch trusted-wake-only"
            )
        missing = [
            fragment
            for fragment in _PROTECTED_REMEDIATION_SECRET_CONTEXT_FRAGMENTS
            if fragment not in text
        ]
        if missing:
            raise ValueError(
                "protected-security-remediation.yml: reviewed author credential boundary changed"
            )
        if "--allow-merge" in text:
            raise ValueError(
                "protected-security-remediation.yml authoring phase must not retain merge authority"
            )

    if name == "ruleset-reconciler.yml":
        if any(
            token in text
            for token in (
                "pull_request:",
                "pull_request_target:",
                "repository_dispatch:",
                "issue_comment:",
                "id-token: write",
                "actions: write",
                "checks: write",
                "contents: write",
                "pull-requests: write",
                "statuses: write",
                "security-events: write",
                "aws-actions/",
            )
        ):
            raise ValueError(
                "ruleset-reconciler.yml must remain accepted-main-only with a read-only native token"
            )
        missing = [
            fragment
            for fragment in _RULESET_RECONCILER_SECRET_CONTEXT_FRAGMENTS
            if fragment not in text
        ]
        if missing:
            raise ValueError(
                "ruleset-reconciler.yml: reviewed administration credential boundary changed"
            )
        if text.count("gh api --method PUT") != 1:
            raise ValueError("ruleset-reconciler.yml must expose exactly one reviewed ruleset PUT")
        if text.count("environment: ruleset-admin-identity") != 1:
            raise ValueError(
                "ruleset-reconciler.yml must isolate credentials to one admin environment"
            )
    if name == "ruleset-drift-sentinel.yml":
        if any(
            token in text
            for token in (
                "pull_request:",
                "push:",
                "repository_dispatch:",
                "issue_comment:",
                "contents: write",
                "actions: write",
                "checks: write",
                "statuses: write",
                "pull-requests: write",
                "security-events: write",
                "id-token: write",
                "environment:",
                "ruleset-admin-identity",
                "${{ secrets.",
                "ADMIN_APP_ID",
                "ADMIN_INSTALLATION_ID",
                "ADMIN_PRIVATE_KEY",
                "app/installations/",
                "permissions[administration]",
                "aws-actions/",
                "ACTIONS_ID_TOKEN_REQUEST_",
                "curl ",
                "wget ",
            )
        ):
            raise ValueError(
                "ruleset-drift-sentinel.yml must remain secret-free and native-read-only"
            )
        missing = [
            fragment for fragment in _RULESET_SENTINEL_READ_ONLY_FRAGMENTS if fragment not in text
        ]
        if missing:
            raise ValueError(
                "ruleset-drift-sentinel.yml: reviewed read-only witness boundary changed"
            )
        mutation_api_re = re.compile(
            r"\bgh\s+api\b[^\n]*(?:(?:--method(?:=|\s+)|-X\s+)(?:POST|PUT|PATCH|DELETE)\b|graphql\b)",
            re.IGNORECASE,
        )
        if mutation_api_re.search(text):
            raise ValueError(
                "ruleset-drift-sentinel.yml contains forbidden repository mutation API form"
            )
        if text.count("gh api") != 3:
            raise ValueError("ruleset-drift-sentinel.yml GitHub API call inventory drifted")
        if text.count("environment:") != 0:
            raise ValueError("ruleset-drift-sentinel.yml must not enter a privileged environment")
    if name == "security-autoheal-pr.yml" and any(
        token in text
        for token in (
            "workflow_run:",
            "status:",
            "schedule:",
            "workflow_dispatch:",
            "repository_dispatch:",
            "environment:",
            "${{ vars.",
            "contents: write",
            "pull-requests: write",
            "checks: write",
            "statuses: write",
            "actions: write",
            "security-events: write",
            "--allow-merge",
            "--reconcile",
            "--plan-routes",
        )
    ):
        raise ValueError(
            "security-autoheal-pr.yml must remain read-only candidate development evidence"
        )
    if name == "security-autoheal.yml":
        if "pull_request:" in text or "repository_dispatch:" in text:
            raise ValueError(
                "security-autoheal.yml must remain accepted-main-only and reject candidate/external mutation triggers"
            )
        missing = [
            fragment
            for fragment in _SECURITY_AUTOHEAL_SECRET_CONTEXT_FRAGMENTS
            if fragment not in text
        ]
        if missing:
            raise ValueError(
                "security-autoheal.yml: reviewed credential consumers moved or changed"
            )
        if "--allow-merge" in text:
            raise ValueError(
                "security-autoheal.yml authoring phase must not retain merge authority"
            )
    if name == "trusted-pr-auto.yml":
        if (
            "workflow_dispatch:" in text
            or "repository_dispatch:" in text
            or "issue_comment:" in text
            or "pull_request_target:" in text
        ):
            raise ValueError(
                "trusted-pr-auto.yml must not expose candidate-ref or external authority triggers"
            )
        missing = [
            fragment for fragment in _TRUSTED_AUTO_SECRET_CONTEXT_FRAGMENTS if fragment not in text
        ]
        if missing:
            raise ValueError(
                "trusted-pr-auto.yml: reviewed trusted-gate credential boundary changed"
            )

    return {
        "workflow": name,
        "aws_authentication": "forbidden",
        "pull_request_target": "forbidden",
        "secrets": dict(sorted(secret_references.items())),
    }


def _contains_required_fragment(text: str, fragment: str) -> bool:
    pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(fragment)}(?![A-Za-z0-9_])")
    return pattern.search(text) is not None


def _verify_owner_ci_identity_guard(text: str) -> None:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ValueError("automatic trusted preflight is not valid Python") from exc

    owner_guards: list[ast.If] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for statement in node.body:
            if not isinstance(statement, ast.Return) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if not isinstance(call.func, ast.Name) or call.func.id != "Wake":
                continue
            if any(
                keyword.arg == "kind"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value == "owner-ci"
                for keyword in call.keywords
            ):
                owner_guards.append(node)
                break

    if len(owner_guards) != 1:
        raise ValueError(
            "automatic trusted preflight lost canonical repository/fork isolation: "
            "owner-ci wake must have exactly one structural identity guard"
        )

    expected = ast.parse(
        'actor.get("login") == EXPECTED_OWNER and '
        'actor.get("id") == EXPECTED_OWNER_ID and '
        'triggering_actor.get("login") == EXPECTED_OWNER and '
        'triggering_actor.get("id") == EXPECTED_OWNER_ID',
        mode="eval",
    ).body
    if ast.dump(owner_guards[0].test, include_attributes=False) != ast.dump(
        expected, include_attributes=False
    ):
        raise ValueError(
            "automatic trusted preflight lost canonical repository/fork isolation: "
            "owner-ci wake identity guard changed"
        )


def _verify_trusted_preflight(text: str) -> dict[str, str]:
    _verify_owner_ci_identity_guard(text)
    missing = [
        fragment
        for fragment in _REQUIRED_PREFLIGHT_FRAGMENTS
        if not _contains_required_fragment(text, fragment)
    ]
    if missing:
        raise ValueError(
            "automatic trusted preflight lost canonical repository/fork isolation: "
            + "; ".join(missing)
        )
    retired = (
        "EXPECTED_MAINTENANCE_WAKE_WORKFLOW_NAME",
        "EXPECTED_MAINTENANCE_WAKE_WORKFLOW_PATH",
        "PROTECTED_OWNER_WAKE_KIND",
    )
    present = [fragment for fragment in retired if _contains_required_fragment(text, fragment)]
    if present:
        raise ValueError(
            "automatic trusted preflight reintroduced retired direct owner-comment wake authority: "
            + "; ".join(present)
        )
    return {
        "repository": EXPECTED_REPOSITORY,
        "owner": EXPECTED_OWNER,
        "fork_heads": "rejected",
        "external_actors": "rejected",
    }


_FORBIDDEN_TRUSTED_CONTROL_TOKENS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS SDK", re.compile(r"(?i)\b(?:boto3|botocore)\b")),
    (
        "retired external trusted-gate binding",
        re.compile(
            r"(?i)trusted_gate_service|TRUSTED_GATE_(?:CONFIG_PREFIX|TABLE_NAME|POLICY_SHA256)|"
            r"amazonaws\.com|/github/webhook|x-github-delivery|x-hub-signature-256"
        ),
    ),
)


def _verify_no_external_gate_dependency(label: str, text: str) -> None:
    for authority, pattern in _FORBIDDEN_TRUSTED_CONTROL_TOKENS:
        if pattern.search(text):
            raise ValueError(f"{label} reintroduced external trusted-gate dependency: {authority}")


def _verify_retired_external_trusted_gate(root: Path) -> None:
    retired = root / "scripts" / "trusted_gate_service"
    if retired.exists() or retired.is_symlink():
        raise ValueError("retired external trusted-gate runtime reintroduced")


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    _verify_retired_external_trusted_gate(root)
    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise ValueError("workflow directory must be an owned regular directory")

    names: list[str] = []
    for entry in sorted(workflow_dir.iterdir(), key=lambda item: item.name):
        if entry.suffix not in {".yml", ".yaml"}:
            raise ValueError(f"unexpected non-workflow entry in workflow directory: {entry.name}")
        names.append(entry.name)
        if len(names) > MAX_WORKFLOW_ENTRIES:
            raise ValueError("workflow directory exceeds bounded entry limit")

    if set(names) != EXPECTED_WORKFLOW_NAMES:
        raise ValueError(
            "workflow set differs from reviewed cloud-authority contract: "
            f"expected {sorted(EXPECTED_WORKFLOW_NAMES)}, got {sorted(names)}"
        )

    workflows: list[dict[str, Any]] = []
    for name in names:
        text = _read_regular_text(
            workflow_dir / name,
            max_bytes=MAX_WORKFLOW_BYTES,
            label=f"workflow {name}",
        )
        workflows.append(_verify_workflow_text(name, text))

    preflight_text = _read_regular_text(
        root / "scripts" / "auto_trusted_preflight.py",
        max_bytes=MAX_PREFLIGHT_BYTES,
        label="automatic trusted preflight",
    )
    _verify_no_external_gate_dependency("automatic trusted preflight", preflight_text)
    preflight = _verify_trusted_preflight(preflight_text)

    for relative in (
        "scripts/auto_trusted_bot_admission.py",
        "scripts/auto_trusted_report.py",
        "scripts/trusted_pr_control.py",
    ):
        control_text = _read_regular_text(
            root / relative,
            max_bytes=256 * 1024,
            label=relative,
        )
        _verify_no_external_gate_dependency(relative, control_text)

    return {
        "schema_version": 1,
        "canonical_repository": EXPECTED_REPOSITORY,
        "github_actions_aws_authentication": "forbidden",
        "external_trusted_gate_runtime": "retired",
        "external_trusted_gate_dependency": "forbidden",
        "fork_cloud_authority": "denied",
        "workflow_count": len(workflows),
        "workflows": workflows,
        "trusted_preflight": preflight,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify fork isolation and GitHub-native-only cloud authority"
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    verify_repository(args.root)
    print(
        json.dumps(
            {"schema_version": 1, "result": "PASS", "verifier": "fork-cloud-authority"},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
