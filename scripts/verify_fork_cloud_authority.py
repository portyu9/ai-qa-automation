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
    "manual-validation.yml",
    "post-merge-ci.yml",
    "protected-security-remediation.yml",
    "release-candidate.yml",
    "security-autoheal-pr.yml",
    "security-autoheal.yml",
    "trusted-pr-auto.yml",
}
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_WORKFLOW_ENTRIES = 16
MAX_PREFLIGHT_BYTES = 64 * 1024

# GitHub Actions must not become an AWS authentication plane. This repository's AWS
# authority is intentionally external to Actions and is admitted by the Trusted PR Gate.
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
    ("indirect GitHub secret reference", re.compile(r"(?i)\bsecrets\s*\[")),
    ("inherited GitHub secrets", re.compile(r"(?i)\bsecrets\s*:\s*inherit\b")),
    ("pull_request_target trigger", re.compile(r"(?i)\bpull_request_target\b")),
)

_ALLOWED_SECRET_REFERENCE_COUNTS: dict[str, Counter[str]] = {
    "dependency-governance.yml": Counter(
        {"GITHUB_TOKEN": 3, "PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 1}
    ),
    "manual-validation.yml": Counter({"ANTHROPIC_API_KEY": 2}),
    "protected-security-remediation.yml": Counter({"PROTECTED_REMEDIATION_APP_PRIVATE_KEY": 1}),
    "security-autoheal.yml": Counter(),
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
    "- name: Attempt one bounded transient recovery\n        if: steps.revision.outputs.current == 'true' && (github.event_name == 'workflow_run' || github.event_name == 'schedule')\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
    "- name: Mint independent promotion author token\n        if: steps.revision.outputs.current == 'true'\n        id: promotion-author-app",
    "private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
    "permission-contents: write",
    "permission-pull-requests: write",
    "- name: Reconcile exact-subject Python dependency promotion\n        if: steps.revision.outputs.current == 'true'\n        id: python_promotion\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          PROMOTION_AUTHOR_TOKEN: ${{ steps.promotion-author-app.outputs.token }}",
    "- name: Reconcile Dependabot action merge authority\n        if: steps.revision.outputs.current == 'true' && steps.python_promotion.outputs.merged != 'true'\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
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
    "python .github/scripts/protected_security_remediation.py --reconcile --allow-merge",
)
_POST_MERGE_CI_AUTHORITY_FRAGMENTS = (
    "on:\n  workflow_run:\n    workflows: [dependency-governance, Security Auto-Heal]\n    types: [completed]",
    'case "$UPSTREAM_NAME:$UPSTREAM_PATH" in',
    '"dependency-governance:.github/workflows/dependency-governance.yml")',
    '"Security Auto-Heal:.github/workflows/security-autoheal.yml")',
    "permissions:\n  contents: read",
    'test "$UPSTREAM_REPOSITORY" = "$GITHUB_REPOSITORY"',
    'test "$UPSTREAM_HEAD_REPOSITORY" = "$GITHUB_REPOSITORY"',
    'test "$live_main" = "$SUBJECT_SHA"',
    "permissions:\n      checks: write\n      contents: read\n    uses: ./.github/workflows/ci.yml",
    "permissions:\n      actions: read\n      checks: write\n      contents: read\n      security-events: write\n    uses: ./.github/workflows/codeql.yml",
)

_SECURITY_AUTOHEAL_SECRET_CONTEXT_FRAGMENTS = (
    "if: >-\n      github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch' ||\n      (github.event_name == 'workflow_run' &&\n       github.event.workflow_run.conclusion == 'success' &&\n       github.event.workflow_run.head_repository.full_name == github.repository &&\n       (github.event.workflow_run.head_branch == 'main' ||\n        github.event.workflow_run.name == 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'))",
    "- name: Plan exact-main deterministic security routes\n        if: steps.revision.outputs.current == 'true'\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: >-\n          python .github/scripts/security_autoheal.py\n          --plan-routes",
    "- name: Persist exact-run route plan before mutation\n        if: steps.revision.outputs.current == 'true'\n        id: route-plan-artifact\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
    '- name: Reconcile exact-subject CodeQL remediations from persisted routes\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: >-\n          python .github/scripts/security_autoheal.py\n          --reconcile\n          --allow-merge\n          --route-plan "$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json"',
)

_TRUSTED_AUTO_SECRET_CONTEXT_FRAGMENTS = (
    "issue_comment:\n    types: [created]",
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
    'event.get("action") != "created"',
    'not isinstance(issue.get("pull_request"), dict)',
    'api.get(f"/repos/{EXPECTED_REPOSITORY}/issues/comments/{comment_id}")',
    'live_comment.get("body") != body',
    'os.environ.get("GITHUB_REF", "") != f"refs/heads/{EXPECTED_DEFAULT_BRANCH}"',
    'os.environ.get("GITHUB_SHA", "") != trusted_sha',
    'os.environ.get("GITHUB_RUN_ATTEMPT", "") != "1"',
    'os.environ.get("GITHUB_WORKFLOW_REF", "") != expected_workflow_ref',
    'sender.get("login") != EXPECTED_OWNER',
    'sender.get("id") != EXPECTED_OWNER_ID',
    'comment_user.get("login") != EXPECTED_OWNER',
    'comment_user.get("id") != EXPECTED_OWNER_ID',
    "if not admission.protected_changes:",
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
                "post-merge-ci.yml must remain exact accepted-main validation without cloud or merge authority"
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
    if name == "trusted-pr-auto.yml":
        if (
            "workflow_dispatch:" in text
            or "repository_dispatch:" in text
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
                "trusted-pr-auto.yml: reviewed protected-maintenance credential boundary changed"
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
    return {
        "repository": EXPECTED_REPOSITORY,
        "owner": EXPECTED_OWNER,
        "fork_heads": "rejected",
        "external_actors": "rejected",
    }


def verify_repository(root: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
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
    preflight = _verify_trusted_preflight(preflight_text)

    return {
        "schema_version": 1,
        "canonical_repository": EXPECTED_REPOSITORY,
        "github_actions_aws_authentication": "forbidden",
        "fork_cloud_authority": "denied",
        "workflow_count": len(workflows),
        "workflows": workflows,
        "trusted_preflight": preflight,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify fork isolation and absence of GitHub Actions AWS authority"
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
