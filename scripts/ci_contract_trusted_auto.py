from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

_BASE_PATH = Path(__file__).with_name("ci_contract_base.py")
_BASE_SPEC = importlib.util.spec_from_file_location("aiqa_ci_contract_base", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load frozen CI contract base verifier")
_base = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = _base
_BASE_SPEC.loader.exec_module(_base)

# Preserve the complete hardened verifier helper API because the top-level contract and
# adversarial tests import private helpers directly. This extension owns only the automatic
# trusted workflow contract; ordinary CI authority is verified by verify_ci_contract.py.
for _export_name in dir(_base):
    if not _export_name.startswith("__"):
        globals()[_export_name] = getattr(_base, _export_name)
del _export_name

EXPECTED_WORKFLOW_NAMES = {
    "ci.yml",
    "manual-validation.yml",
    "trusted-pr-auto.yml",
}
EXPECTED_TRUSTED_AUTO_WORKFLOW_BLOB_SHA = (
    "828c513950fb17b76dfd66bb0f01e181187ff9ef"  # pragma: allowlist secret
)
EXPECTED_BASE_VERIFIER_BLOB_SHA = (
    "175e40adafaf8cf6ac702291ecee237a02a7c10e"  # pragma: allowlist secret
)
TRUSTED_AUTO_WORKFLOW_NAME = "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"
TRUSTED_AUTO_SOURCE_WORKFLOWS = (
    "CI — ƳƤ AI QA Automation Framework",
    "CodeQL",
)
TRUSTED_AUTO_PROTECTED_PATHS = (
    ".github",
    "scripts",
    ".claude",
    ".dockerignore",
    ".gitattributes",
    ".mcp.json",
    ".pre-commit-config.yaml",
    "CLAUDE.md",
    "Dockerfile",
    "evals",
    "examples",
    "pyproject.toml",
    "requirements",
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)

_base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES


def _job_permissions(job: str) -> dict[str, str]:
    semantic = _base._semantic_text(job)
    lines = semantic.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "    permissions:"]
    if len(starts) != 1:
        raise ValueError("trusted automatic job must contain exactly one permissions block")
    values: dict[str, str] = {}
    for line in lines[starts[0] + 1 :]:
        if line.startswith("    ") and not line.startswith("      "):
            break
        if not line.strip():
            continue
        if not line.startswith("      ") or ":" not in line.strip():
            raise ValueError("trusted automatic job permissions block is malformed")
        key, value = line.strip().split(":", 1)
        if key in values:
            raise ValueError("trusted automatic job permissions contain duplicate keys")
        values[key] = value.strip()
    if not values:
        raise ValueError("trusted automatic job permissions block must not be empty")
    return values


def _verify_frozen_base() -> None:
    path = Path(_base.__file__)
    if path.is_symlink() or not path.is_file():
        raise ValueError("CI contract base verifier must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _base._git_blob_sha1(text) != EXPECTED_BASE_VERIFIER_BLOB_SHA:
        raise ValueError("CI contract base verifier differs from the frozen hardened definition")


def _verify_trusted_auto_workflow(text: str) -> dict[str, Any]:
    semantic = _base._semantic_text(text)
    if _base._workflow_structure_sha1(text) != EXPECTED_TRUSTED_AUTO_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "trusted-pr-auto.yml non-action structure differs from reviewed trust authority"
        )

    on_block = _base._semantic_text(_base._top_level_block(text, "on")).strip("\n")
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            '    workflows: ["CI — ƳƤ AI QA Automation Framework", "CodeQL"]',
            "    types: [completed]",
            "  schedule:",
            '    - cron: "*/5 * * * *"',
        )
    )
    if on_block != expected_on:
        raise ValueError(
            "trusted-pr-auto.yml must be triggered only by completed reviewed CI/CodeQL runs "
            "or the reviewed five-minute schedule"
        )

    concurrency = _base._semantic_text(_base._top_level_block(text, "concurrency"))
    required_concurrency = (
        "concurrency:",
        "  group: trusted-pr-auto-${{ github.event_name == 'schedule' && 'scheduled-bot-reconcile' || github.event.workflow_run.id }}",
        "  cancel-in-progress: false",
    )
    for fragment in required_concurrency:
        if fragment not in concurrency:
            raise ValueError("trusted automatic schedule concurrency contract drifted")

    bot_codeql = _base._semantic_text(_base._job_block(text, "bot-codeql"))
    semantic_without_bot_codeql = semantic.replace(bot_codeql, "")
    permissions = _base._permissions(_base._top_level_block(text, "permissions"))
    if permissions != {"actions": "read", "contents": "read", "pull-requests": "read"}:
        raise ValueError("trusted-pr-auto.yml top-level token must be exactly read-only")
    if _base.WRITE_PERMISSION_RE.search(semantic_without_bot_codeql):
        raise ValueError(
            "trusted-pr-auto.yml native GitHub token may write only security-events "
            "inside the reviewed bot CodeQL job"
        )
    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_dispatch:",
        "continue-on-error: true",
        "ubuntu-latest",
        "playwright install",
        "sudo ",
        "apt-get ",
        "apt install ",
        "${{ secrets.GITHUB_TOKEN }}",
    ):
        if forbidden in semantic:
            raise ValueError(f"trusted-pr-auto.yml contains forbidden authority token: {forbidden}")
    if _base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError("trusted-pr-auto.yml dependency caching is forbidden")
    if '"3.13.15"' in semantic or "dev-py313.lock" in semantic or "py313" in semantic:
        raise ValueError("trusted-pr-auto.yml contains stale Python 3.13 CI authority")

    preflight = _base._semantic_text(_base._job_block(text, "preflight"))
    required_preflight = (
        "    name: Automatic Trusted Admission",
        "    if: ${{ github.event_name == 'schedule' || github.event.workflow_run.conclusion == 'success' }}",
        "      actions: read",
        "      checks: read",
        "      contents: read",
        "      pull-requests: read",
        "      lane: ${{ steps.admission.outputs.lane }}",
        "      head_ref: ${{ steps.admission.outputs.head_ref }}",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        '        run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python scripts/auto_trusted_preflight.py \\",
        '            --event "$GITHUB_EVENT_PATH" \\',
        '            --event-name "$GITHUB_EVENT_NAME" \\',
        '            --github-output "$GITHUB_OUTPUT"',
        "            owner-routine)",
        "            dependabot-actions|dependency-promotion|security-autoheal)",
        "            none)",
    )
    for fragment in required_preflight:
        if fragment not in preflight:
            raise ValueError(
                f"trusted automatic preflight is missing reviewed fragment: {fragment}"
            )
    if "needs.preflight.outputs.merge_sha" in preflight:
        raise ValueError("trusted automatic preflight must not checkout or execute candidate bytes")
    if "CI_SUBJECT_SHA" in preflight or "github.event.workflow_run.head_sha" in preflight:
        raise ValueError("trusted automatic preflight must retain trusted workflow identity")

    bot_authority = _base._semantic_text(_base._job_block(text, "bot-authority"))
    required_bot = (
        "    name: Governed Bot Provenance + Authority",
        "    needs: preflight",
        "needs.preflight.outputs.lane != 'owner-routine'",
        "      actions: read",
        "      checks: read",
        "      contents: read",
        "      pull-requests: read",
        "      security-events: read",
        "          ref: ${{ needs.preflight.outputs.trusted_sha }}",
        "          persist-credentials: false",
        '          python-version: "3.11.16"',
        '          python-version: "3.14.7"',
        "PROMOTION_PYTHON311",
        "PROMOTION_PYTHON314",
        "scripts/auto_trusted_bot_admission.py",
        "--mode full",
        '--lane "$LANE"',
        '--expected-head-sha "$EXPECTED_HEAD_SHA"',
        '--expected-base-sha "$EXPECTED_BASE_SHA"',
        '--expected-merge-sha "$EXPECTED_MERGE_SHA"',
    )
    for fragment in required_bot:
        if fragment not in bot_authority:
            raise ValueError(f"governed bot authority is missing reviewed fragment: {fragment}")
    if "${{ secrets." in bot_authority or "write" in _job_permissions(bot_authority).values():
        raise ValueError("governed bot authority must remain secret-free and read-only")

    if "needs.bot-authority.result" in bot_authority:
        raise ValueError("governed bot authority must not self-reference its own result")

    cancellation_safe_jobs = (
        "subject-guard",
        "supply-chain",
        "quality",
        "deterministic-evals",
        "security",
        "browser-reference-sut",
        "bot-codeql",
        "required-gate",
        "trusted-status",
    )
    for job_id in cancellation_safe_jobs:
        job = _base._semantic_text(_base._job_block(text, job_id))
        if "    if: ${{ !cancelled()" not in job:
            raise ValueError(
                f"trusted automatic job {job_id} must override skipped dependency propagation "
                "without running after cancellation"
            )

    subject_guard = _base._semantic_text(_base._job_block(text, "subject-guard"))
    required_guard = (
        "    name: Exact Subject + Protected Authority Guard",
        "    needs: [preflight, bot-authority]",
        "!cancelled()",
        "needs.preflight.result == 'success'",
        "needs.preflight.outputs.lane == 'owner-routine' || needs.bot-authority.result == 'success'",
        "          ref: ${{ needs.preflight.outputs.merge_sha }}",
        "          persist-credentials: false",
        "          ADMISSION_LANE: ${{ needs.preflight.outputs.lane }}",
        "          BOT_AUTHORITY_RESULT: ${{ needs.bot-authority.result }}",
        '          test "$EXPECTED_BASE_SHA" = "$EXPECTED_TRUSTED_SHA"',
        '          test "$(git rev-parse HEAD)" = "$EXPECTED_MERGE_SHA"',
        '          read -r merge_sha base_sha head_sha extra_parent < <("${git_clean_env[@]}" /usr/bin/git rev-list --parents -n 1 "$EXPECTED_MERGE_SHA")',
        '          if test "$ADMISSION_LANE" = "owner-routine"; then',
        "              dependabot-actions|dependency-promotion|security-autoheal) ;;",
        '            test "$BOT_AUTHORITY_RESULT" = "success"',
        '            "${git_clean_env[@]}" /usr/bin/git diff --quiet "$EXPECTED_HEAD_SHA" "$EXPECTED_MERGE_SHA" --',
    )
    for fragment in required_guard:
        if fragment not in subject_guard:
            raise ValueError(
                f"trusted automatic subject guard is missing reviewed fragment: {fragment}"
            )
    for protected_path in TRUSTED_AUTO_PROTECTED_PATHS:
        if f"            {protected_path}\n" not in subject_guard:
            raise ValueError(f"trusted automatic subject guard does not protect {protected_path}")

    candidate_checkout = "ref: ${{ needs.preflight.outputs.merge_sha }}"
    trusted_checkout = "ref: ${{ needs.preflight.outputs.trusted_sha }}"
    if semantic.count(candidate_checkout) != 6:
        raise ValueError("trusted automatic validation must have exactly six candidate checkouts")
    if semantic.count("ref: ${{ github.sha }}") != 1:
        raise ValueError("trusted automatic preflight must have exactly one event-trusted checkout")
    if semantic.count(trusted_checkout) != 2:
        raise ValueError(
            "trusted automatic bot policy and reporter must have exactly two trusted-base checkouts"
        )
    bot_head_checkout = "ref: ${{ needs.preflight.outputs.head_sha }}"
    if semantic.count(bot_head_checkout) != 1:
        raise ValueError("trusted automatic bot CodeQL must have exactly one bot-head checkout")
    if semantic.count("persist-credentials: false") != 10:
        raise ValueError("every trusted automatic checkout must disable persisted credentials")

    candidate_subject_binding = (
        "    env:\n      CI_SUBJECT_SHA: ${{ needs.preflight.outputs.merge_sha }}\n"
    )
    validation_jobs = (
        "supply-chain",
        "quality",
        "deterministic-evals",
        "security",
        "browser-reference-sut",
    )
    expected_validation_conditions = {
        "supply-chain": (
            "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
            "needs.preflight.outputs.eligible == 'true' && "
            "needs.subject-guard.result == 'success' }}"
        ),
        "quality": (
            "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
            "needs.preflight.outputs.eligible == 'true' && "
            "needs.subject-guard.result == 'success' && "
            "needs.supply-chain.result == 'success' }}"
        ),
        "deterministic-evals": (
            "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
            "needs.preflight.outputs.eligible == 'true' && "
            "needs.subject-guard.result == 'success' && "
            "needs.supply-chain.result == 'success' }}"
        ),
        "security": (
            "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
            "needs.preflight.outputs.eligible == 'true' && "
            "needs.subject-guard.result == 'success' && "
            "needs.supply-chain.result == 'success' }}"
        ),
        "browser-reference-sut": (
            "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
            "needs.preflight.outputs.eligible == 'true' && "
            "needs.subject-guard.result == 'success' && "
            "needs.supply-chain.result == 'success' }}"
        ),
    }
    for job_id in validation_jobs:
        job = _base._semantic_text(_base._job_block(text, job_id))
        if expected_validation_conditions[job_id] not in job:
            raise ValueError(
                f"trusted automatic validation job {job_id} must be cancellation-safe and "
                "explicitly direct-needs-bound"
            )
        if candidate_checkout not in job:
            raise ValueError(
                f"trusted automatic validation job {job_id} is not merge-subject-bound"
            )
        if candidate_subject_binding not in job:
            raise ValueError(
                f"trusted automatic validation job {job_id} must bind CI_SUBJECT_SHA "
                "to the exact prospective merge"
            )
        if "${{ secrets." in job:
            raise ValueError(f"trusted automatic validation job {job_id} must be secret-free")
        if "persist-credentials: false" not in job:
            raise ValueError(f"trusted automatic validation job {job_id} must disable credentials")

    quality_lanes = _base._verify_quality_lane_contract(text, name="trusted-pr-auto.yml")

    bot_codeql_permissions = _job_permissions(bot_codeql)
    if bot_codeql_permissions != {
        "actions": "read",
        "contents": "read",
        "security-events": "write",
    }:
        raise ValueError("trusted bot CodeQL permissions differ from the reviewed minimum")
    required_bot_codeql = (
        "    name: Trusted Bot CodeQL",
        "    needs: [preflight, subject-guard]",
        "    if: ${{ !cancelled() && needs.preflight.result == 'success' && needs.preflight.outputs.eligible == 'true' && needs.preflight.outputs.lane != 'owner-routine' && needs.subject-guard.result == 'success' }}",
        bot_head_checkout,
        "          persist-credentials: false",
        "          EXPECTED_HEAD_SHA: ${{ needs.preflight.outputs.head_sha }}",
        '        run: test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD_SHA"',
        "      - name: Acquire verified CodeQL 2.27.0 bundle",
        "        id: codeql-tools",
        "release_api='https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.27.0'",
        "asset_url='https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst'",
        're.fullmatch(r"sha256:[0-9a-f]{64}", digest)',
        'test "$observed_sha" = "$expected_sha"',
        "      - name: Initialize governed bot CodeQL",
        "          tools: ${{ steps.codeql-tools.outputs.path }}",
        "          languages: python",
        "          queries: security-extended",
        "      - name: Analyze exact governed bot branch",
        '        env:\n          PYTHONSAFEPATH: ""',
        "          ref: refs/heads/${{ needs.preflight.outputs.head_ref }}",
        "          sha: ${{ needs.preflight.outputs.head_sha }}",
    )
    for fragment in required_bot_codeql:
        if fragment not in bot_codeql:
            raise ValueError(f"trusted bot CodeQL is missing reviewed fragment: {fragment}")
    if bot_codeql.count("      - name: Acquire verified CodeQL 2.27.0 bundle") != 1:
        raise ValueError("trusted bot CodeQL must acquire exactly one verified local bundle")
    if bot_codeql.count("          tools: ${{ steps.codeql-tools.outputs.path }}") != 1:
        raise ValueError("trusted bot CodeQL must use exactly one verified local bundle path")
    if semantic.count('          PYTHONSAFEPATH: ""') != 1:
        raise ValueError(
            "trusted bot CodeQL must disable Python safe-path only for extractor analysis"
        )
    if "${{ secrets." in bot_codeql:
        raise ValueError("trusted bot CodeQL must remain secret-free")

    required_gate = _base._semantic_text(_base._job_block(text, "required-gate"))
    required_gate_condition = (
        "    if: ${{ !cancelled() && needs.preflight.result == 'success' && "
        "needs.preflight.outputs.eligible == 'true' }}"
    )
    if required_gate_condition not in required_gate:
        raise ValueError("automatic trusted aggregate cancellation/eligibility guard drifted")
    for dependency in (
        "subject-guard",
        "quality",
        "deterministic-evals",
        "supply-chain",
        "security",
        "browser-reference-sut",
    ):
        if (
            f'          test "${{{{ needs.{dependency}.result }}}}" = "success"'
            not in required_gate
        ):
            raise ValueError(f"automatic trusted aggregate does not require {dependency}")
    for fragment in (
        '          if test "${{ needs.preflight.outputs.lane }}" = "owner-routine"; then',
        '            test "${{ needs.bot-codeql.result }}" = "skipped"',
        '            test "${{ needs.bot-codeql.result }}" = "success"',
    ):
        if fragment not in required_gate:
            raise ValueError("automatic trusted aggregate bot CodeQL policy drifted")

    reporter = _base._semantic_text(_base._job_block(text, "trusted-status"))
    required_reporter = (
        "    name: Automatic Trusted PR Gate Reporter",
        "    if: ${{ !cancelled() && needs.preflight.result == 'success' && needs.preflight.outputs.eligible == 'true' }}",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "      actions: read",
        "      checks: read",
        "      contents: read",
        "      pull-requests: read",
        "      security-events: read",
        trusted_checkout,
        "      - name: Revalidate automatic trusted admission",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python scripts/auto_trusted_preflight.py \\",
        "      - name: Require exact final admission identity",
        '          test "$FINAL_ELIGIBLE" = "true"',
        '          test "$FINAL_LANE" = "$EXPECTED_LANE"',
        "              dependabot-actions|dependency-promotion|security-autoheal) ;;",
        '          test "$FINAL_MERGE_SHA" = "$EXPECTED_MERGE_SHA"',
        '          test "$FINAL_TRUSTED_SHA" = "$GITHUB_SHA"',
        "      - name: Reprove governed bot authority immediately before App publication",
        "scripts/auto_trusted_bot_admission.py",
        "--mode terminal",
        "      - name: Mint dedicated Trusted PR Gate token",
        "          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Publish automatic exact-subject trusted status",
        "          GITHUB_TOKEN: ${{ steps.trusted-app.outputs.token }}",
        "          python scripts/auto_trusted_report.py \\",
    )
    for fragment in required_reporter:
        if fragment not in reporter:
            raise ValueError(f"automatic trusted reporter is missing reviewed fragment: {fragment}")
    if "CI_SUBJECT_SHA:" in reporter:
        raise ValueError("trusted automatic reporter must retain trusted workflow identity")
    if semantic.count("${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("automatic trusted App private key must have exactly one consumer")
    if semantic.count("${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}") != 1:
        raise ValueError("automatic trusted App client ID must have exactly one consumer")
    if "${{ secrets." in semantic.replace(reporter, ""):
        raise ValueError("automatic trusted environment secrets must be isolated to reporter")

    revalidate_position = reporter.index("      - name: Revalidate automatic trusted admission")
    final_identity_position = reporter.index("      - name: Require exact final admission identity")
    terminal_bot_position = reporter.index(
        "      - name: Reprove governed bot authority immediately before App publication"
    )
    mint_position = reporter.index("      - name: Mint dedicated Trusted PR Gate token")
    publish_position = reporter.index(
        "      - name: Publish automatic exact-subject trusted status"
    )
    if not (
        revalidate_position
        < final_identity_position
        < terminal_bot_position
        < mint_position
        < publish_position
    ):
        raise ValueError("automatic trusted reporter authority steps are out of reviewed order")

    return {
        "trigger": "workflow_run:completed:reviewed-ci-or-codeql+schedule:5m",
        "wake_signal": "owner-pull-request-ci-or-trusted-main-scheduled-bot-reconciliation",
        "trusted_definition": "default-branch-workflow-run-or-schedule-revision",
        "candidate_execution_guard": (
            "owner-zero-protected-drift-or-exact-governed-bot-provenance"
        ),
        "governed_bot_lanes": [
            "dependabot-actions",
            "dependency-promotion",
            "security-autoheal",
        ],
        "protected_paths": list(TRUSTED_AUTO_PROTECTED_PATHS),
        "validation_subject": "live-prospective-merge-sha",
        "candidate_subject_binding": "job-level-exact-prospective-merge",
        "needs_skip_policy": "not-cancelled-plus-explicit-direct-needs-success",
        "validation_authority": (
            "secret-free;read-only-except-bot-codeql-security-events-write-before-reporter"
        ),
        "quality_lanes": quality_lanes,
        "terminal_revalidation": "fresh-live-admission-plus-terminal-bot-authority-reproof",
        "status_writer": "dedicated-github-app",
        "maintenance_authority": (
            "autonomous-governed-bots;external-one-shot-only-for-unrecognized-protected-change"
        ),
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }
