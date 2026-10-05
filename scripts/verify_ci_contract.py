from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

_TRUSTED_AUTO_PATH = Path(__file__).with_name("ci_contract_trusted_auto.py")
_TRUSTED_AUTO_SPEC = importlib.util.spec_from_file_location(
    "aiqa_ci_contract_trusted_auto",
    _TRUSTED_AUTO_PATH,
)
if _TRUSTED_AUTO_SPEC is None or _TRUSTED_AUTO_SPEC.loader is None:
    raise RuntimeError("unable to load frozen trusted-auto CI contract extension")
_trusted_auto = importlib.util.module_from_spec(_TRUSTED_AUTO_SPEC)
sys.modules[_TRUSTED_AUTO_SPEC.name] = _trusted_auto
_TRUSTED_AUTO_SPEC.loader.exec_module(_trusted_auto)

# Preserve the complete hardened verifier API because adversarial tests import private
# helpers directly. The trusted-auto extension itself re-exports the hardened base.
for _export_name in dir(_trusted_auto):
    if not _export_name.startswith("__"):
        globals()[_export_name] = getattr(_trusted_auto, _export_name)
del _export_name

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
EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA = (
    "c0061b9775a4d4d3e11916e79ca11923b3b58591"  # pragma: allowlist secret
)
EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (
    "b94cb5db4f3ae34f6b6b925acd508cadbec5bab1"  # pragma: allowlist secret
)
EXPECTED_CODEQL_WORKFLOW_BLOB_SHA = (
    "645a816ac6fa87f25554c6f0c43d74d0595207ff"  # pragma: allowlist secret
)
EXPECTED_POST_MERGE_CI_WORKFLOW_BLOB_SHA = (
    "0132caa81eaca5024e28196c6f49289fcf2f4d4e"  # pragma: allowlist secret
)
EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA = (
    "49c3d4d79fd67602160b7752f1da345a7ad4dd61"  # pragma: allowlist secret
)
EXPECTED_DEPENDENCY_GOVERNANCE_PR_WORKFLOW_BLOB_SHA = (
    "e5ad28155ff53aed21a61cbaea9cc70d87c313be"  # pragma: allowlist secret
)
EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA = (
    "c30b4b2a23c9ad436a66e30fb2e6e189c2695899"  # pragma: allowlist secret
)
EXPECTED_DEPENDENCY_TRUSTED_MERGE_WORKFLOW_BLOB_SHA = (
    "00a76b537edaf703a7420eecad3b310b276bffed"  # pragma: allowlist secret
)
EXPECTED_SECURITY_AUTOHEAL_PR_WORKFLOW_BLOB_SHA = (
    "e793b25b28ca81b34a05a37eb87ca38fc00f2e2e"  # pragma: allowlist secret
)
EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA = (
    "180fcfa89486abaae0940a44e59eac73f134dbb7"  # pragma: allowlist secret
)
EXPECTED_PROTECTED_REMEDIATION_WORKFLOW_BLOB_SHA = (
    "91aa46ab729d3e32708f08b255dfeb8ab0cad927"  # pragma: allowlist secret
)
EXPECTED_RULESET_RECONCILER_WORKFLOW_BLOB_SHA = (
    "392096edc51fc2353f36c68a216003d394bc3720"  # pragma: allowlist secret
)
EXPECTED_RULESET_DRIFT_SENTINEL_WORKFLOW_BLOB_SHA = (
    "149a1c8e05a89f1f26ce9b9e8995df580512c726"  # pragma: allowlist secret
)
EXPECTED_RULESET_DRIFT_WITNESS_BLOB_SHA = (
    "ffd67e15118750937a80ccd400248bcab37ff4f2"  # pragma: allowlist secret
)
EXPECTED_PROTECTED_AUTHOR_ACTION_SHA = (
    "bcd2ba49218906704ab6c1aa796996da409d3eb1"  # pragma: allowlist secret
)
EXPECTED_CODEQL_MAJOR = 4
CODEQL_ACTION_RE = re.compile(
    r"^\s*uses:\s*(github/codeql-action/(?:init|analyze))@([0-9a-f]{40})"
    r"\s+#\s+v(\d+(?:\.\d+){0,2})\s*$",
    re.MULTILINE,
)
EXPECTED_AUTOMATIC_WORKFLOW_BLOB_SHA = EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA

_trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
_trusted_auto._base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
_trusted_auto._base.ADDITIONAL_ALLOWED_ACTION_WORKFLOWS["actions/create-github-app-token"] = (
    frozenset(
        {"dependency-governance.yml", "protected-security-remediation.yml", "security-autoheal.yml"}
    )
)


def _verify_frozen_trusted_auto_extension() -> None:
    path = Path(_trusted_auto.__file__)
    if path.is_symlink() or not path.is_file():
        raise ValueError("trusted-auto CI contract extension must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA:
        raise ValueError("trusted-auto CI contract extension differs from the frozen definition")


def _verify_ordinary_checkout_binding(text: str) -> int:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    checkout = f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}"
    checkout_count = semantic.count(checkout)
    if checkout_count != base.EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT:
        raise ValueError("ci.yml: checkout count must equal the five ordinary validation subjects")
    if semantic.count("ref: ${{ env.CI_SUBJECT_SHA }}") != checkout_count:
        raise ValueError("ci.yml: every validation checkout must bind to env.CI_SUBJECT_SHA")
    if semantic.count("persist-credentials: false") != checkout_count:
        raise ValueError("ci.yml: every checkout must disable persisted credentials")
    if semantic.count('test "$(git rev-parse HEAD)" = "$CI_SUBJECT_SHA"') != checkout_count:
        raise ValueError("ci.yml: every checkout must verify CI_SUBJECT_SHA")
    if "ref: ${{ github.sha }}" in semantic:
        raise ValueError("ci.yml: checkout authority must flow only through CI_SUBJECT_SHA")
    return checkout_count


def _verify_ordinary_ci_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "ci.yml"
    semantic = base._semantic_text(text)

    expected_on = "\n".join(
        (
            "on:",
            "  pull_request:",
            "    branches: [main]",
            "    types: [opened, synchronize, reopened, ready_for_review]",
            "  push:",
            "    branches: [main]",
            "  merge_group:",
            "  workflow_call:",
            "    inputs:",
            "      subject_sha:",
            "        description: Exact current-main commit a trusted reusable caller validates",
            "        required: false",
            "        type: string",
            "  workflow_dispatch:",
            "    inputs:",
            "      subject_sha:",
            "        description: Exact commit the explicit CI dispatch requires evidence for",
            "        required: true",
            "        type: string",
            "      subject_ref:",
            "        description: Exact main, Dependabot Actions, or generated-maintenance branch containing subject_sha",
            "        required: true",
            "        type: string",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError(
            "ci.yml: trigger set must be exactly pull_request/push/merge_group/workflow_call/workflow_dispatch"
        )
    if base._top_level_keys(base._top_level_block(text, "on")) != {
        "pull_request",
        "push",
        "merge_group",
        "workflow_call",
        "workflow_dispatch",
    }:
        raise ValueError("ci.yml: unreviewed trigger authority is forbidden")

    for forbidden in (
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "ANTHROPIC_API_KEY",
    ):
        if forbidden in semantic:
            raise ValueError(f"{name}: forbidden authority token: {forbidden}")

    env_block = base._semantic_text(base._top_level_block(text, "env")).strip("\n")
    expected_env = "\n".join(
        (
            "env:",
            '  PYTHONUNBUFFERED: "1"',
            '  PYTHONSAFEPATH: "1"',
            '  PIP_DISABLE_PIP_VERSION_CHECK: "1"',
            "  CI_SUBJECT_SHA: ${{ github.sha }}",
        )
    )
    if env_block != expected_env:
        raise ValueError("ci.yml: environment/subject binding differs from reviewed definition")

    base._verify_top_level_read_only_permissions(text, name=name)
    for forbidden in (
        "repository_dispatch:",
        "pull_request_target:",
        "github.event.client_payload",
        "trusted-pr-validation",
        "trusted-status:",
        "Trusted PR Gate Reporter",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "ANTHROPIC_API_KEY",
        "continue-on-error: true",
        "playwright install",
        "sudo ",
        "apt-get ",
        "apt install ",
    ):
        if forbidden in semantic:
            raise ValueError(f"{name}: forbidden authority token: {forbidden}")
    publisher_raw = base._job_block(text, "publish-qualified-subject")
    publisher = base._semantic_text(publisher_raw)
    semantic_without_publisher = semantic.replace(publisher, "")
    if base.WRITE_PERMISSION_RE.search(semantic_without_publisher):
        raise ValueError(f"{name}: write permission is forbidden outside exact-subject publication")
    if semantic.count("checks: write") != 1 or "checks: write" not in publisher:
        raise ValueError(
            f"{name}: generated-maintenance publication must isolate exactly one checks:write grant"
        )
    if base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError(f"{name}: dependency caching is forbidden before reviewed lock authority")
    if "ubuntu-latest" in semantic:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if '"3.11.16"' not in semantic or '"3.14.7"' not in semantic:
        raise ValueError(f"{name}: exact supported Python patch versions are required")
    if '"3.13.15"' in semantic or "dev-py313.lock" in semantic or "py313" in semantic:
        raise ValueError(f"{name}: stale Python 3.13 CI authority is forbidden")
    if "--require-hashes" not in semantic:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in semantic or " --editable" in semantic or " -e ." in semantic:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    if "cancel-in-progress: true" not in base._top_level_block(text, "concurrency"):
        raise ValueError(f"{name}: stale executions must be cancelled on superseding revisions")

    checkout_count = _verify_ordinary_checkout_binding(text)
    dependency_install_count = base._verify_dependency_install_authority(text, name=name)
    project_install_count = base._verify_project_install_authority(text, name=name)
    quality_lanes = base._verify_quality_lane_contract(text, name=name)

    dispatch_subject_override = (
        "    env:\n"
        "      CI_SUBJECT_SHA: ${{ (github.event_name == 'workflow_dispatch' || github.event_name == 'workflow_call') && inputs.subject_sha || github.sha }}\n"
    )
    for job_id in (
        "supply-chain",
        "quality",
        "deterministic-evals",
        "security",
        "browser-reference-sut",
    ):
        job = base._semantic_text(base._job_block(text, job_id))
        if dispatch_subject_override not in job:
            raise ValueError(
                f"ci.yml: validation job {job_id} lacks exact trusted-dispatch subject override"
            )

    supply_chain_raw = base._job_block(text, "supply-chain")
    supply_chain = base._semantic_text(supply_chain_raw)
    dispatch_binding = (
        "      - name: Bind trusted-main dispatch to exact approved subject\n"
        "        if: github.event_name == 'workflow_dispatch'\n"
        "        env:\n"
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}\n"
        "          EXPECTED_SUBJECT_REF: ${{ inputs.subject_ref }}\n"
        "          GH_TOKEN: ${{ github.token }}\n"
    )
    if dispatch_binding not in supply_chain:
        raise ValueError("ci.yml: exact-subject workflow_dispatch binding is missing")
    reusable_binding = (
        "      - name: Bind trusted reusable call to exact current main\n"
        "        if: github.event_name == 'workflow_call' && inputs.subject_sha != ''\n"
        "        env:\n"
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}\n"
        "          GH_TOKEN: ${{ github.token }}\n"
    )
    if reusable_binding not in supply_chain:
        raise ValueError("ci.yml: reusable exact-current-main binding is missing")
    for required_reusable_guard in (
        '[[ "$EXPECTED_SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$GITHUB_REF" = "refs/heads/main"',
        'live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'test "$live_main" = "$EXPECTED_SUBJECT_SHA"',
    ):
        if required_reusable_guard not in supply_chain:
            raise ValueError(
                "ci.yml: reusable exact-current-main guard differs from reviewed definition"
            )
    for required_dispatch_guard in (
        '[[ ! "$EXPECTED_SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$GITHUB_REF" != "refs/heads/main" ]]',
        '[[ "$EXPECTED_SUBJECT_REF" == "main" ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$ ]]',
        'live_subject_sha="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${EXPECTED_SUBJECT_REF}" --jq .object.sha)"',
        'test "$live_subject_sha" = "$EXPECTED_SUBJECT_SHA"',
    ):
        if required_dispatch_guard not in supply_chain:
            raise ValueError(
                "ci.yml: exact-subject workflow_dispatch guard differs from reviewed definition"
            )
    base._require_exact_build_authority_step(supply_chain_raw)
    base._require_exact_verification_install_step(supply_chain_raw)
    base._require_exact_script_step(
        supply_chain_raw,
        step_name=base.DOCUMENTATION_STEP_NAME,
        command=base.DOCUMENTATION_INTEGRITY_COMMAND,
    )
    base._require_exact_script_step(
        supply_chain_raw,
        step_name=base.MERMAID_STEP_NAME,
        command=base.MERMAID_RENDER_COMMAND,
    )
    base._require_exact_runtime_sbom_step(supply_chain_raw)
    base._require_exact_reproducible_build_step(supply_chain_raw)
    base._require_exact_supply_chain_upload_step(supply_chain_raw)

    ordered_steps = (
        base.BUILD_AUTHORITY_STEP_NAME,
        base.VERIFICATION_INSTALL_STEP_NAME,
        base.SUPPLY_CHAIN_VERIFY_STEP_NAME,
        base.RUNTIME_SBOM_STEP_NAME,
        base.REPRODUCIBLE_BUILD_STEP_NAME,
    )
    positions = [supply_chain.index(f"      - name: {step_name}") for step_name in ordered_steps]
    if positions != sorted(positions):
        raise ValueError(
            "ci.yml: supply-chain authority, installation, verification, SBOM, and build steps "
            "are out of reviewed order"
        )
    if supply_chain.count(base.BUILD_AUTHORITY_COMMAND) != 1:
        raise ValueError("ci.yml: build-authority evidence command must execute exactly once")
    if supply_chain.count(base.DOCUMENTATION_INTEGRITY_COMMAND) != 1:
        raise ValueError("ci.yml: documentation integrity command must execute exactly once")
    if supply_chain.count(base.MERMAID_RENDER_COMMAND) != 1:
        raise ValueError("ci.yml: Mermaid render command must execute exactly once")

    browser_reference_raw = base._job_block(text, "browser-reference-sut")
    base._require_exact_hosted_browser_step(browser_reference_raw)

    required_gate_raw = base._job_block(text, "required-gate")
    required_gate = base._semantic_text(required_gate_raw)
    if "    name: Required PR Gate" not in required_gate:
        raise ValueError("ci.yml: stable Required PR Gate name is missing")
    if "    if: ${{ always() }}" not in required_gate:
        raise ValueError("ci.yml: Required PR Gate must execute with if: always()")
    base._require_exact_required_gate_step(required_gate_raw)
    for job in base.AUTOMATIC_REQUIRED_JOBS:
        if f"      - {job}\n" not in required_gate:
            raise ValueError(f"ci.yml: Required PR Gate does not depend on {job}")

    for fragment in (
        "    name: Publish Exact-Subject Required PR Gate",
        "    needs: required-gate",
        "inputs.subject_ref != 'main'",
        "    permissions:\n      checks: write\n      contents: read",
        '[[ "$EXPECTED_SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        "repos/${GITHUB_REPOSITORY}/check-runs",
        'external_id="aiqa-ci-qualification:${EXPECTED_SUBJECT_SHA}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"',
        '{name:"Required PR Gate",head_sha:$head,status:"completed",conclusion:$conclusion',
        'test "$(jq -r \'.external_id\' <<<"$response")" = "$external_id"',
        'test "$(jq -r \'.head_sha\' <<<"$response")" = "$EXPECTED_SUBJECT_SHA"',
    ):
        if fragment not in publisher:
            raise ValueError(
                f"ci.yml: exact-subject Required PR Gate publication contract is missing: {fragment}"
            )
    if "actions/checkout@" in publisher or "${{ secrets." in publisher:
        raise ValueError(
            "ci.yml: exact-subject publication must not execute candidate bytes or consume secrets"
        )

    if base._workflow_structure_sha1(text) != EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "ci.yml non-action structure differs from the reviewed ordinary CI definition"
        )

    return {
        "triggers": ["merge_group", "pull_request", "push", "workflow_call", "workflow_dispatch"],
        "subject": "event-sha-or-trusted-reusable-current-main-or-explicit-qualified-sha",
        "workflow_dispatch_subject": "trusted-main-plus-exact-main-or-generated-maintenance-ref-sha",
        "checkout_count": checkout_count,
        "required_gate": "Required PR Gate",
        "quality_lanes": quality_lanes,
        "prebuild_authority": "exact-lock-and-build-authority-before-validation-installs",
        "dependency_install_count": dependency_install_count,
        "dependency_install_authority": "exact-reviewed-locks-preinstall-and-postinstall-revalidated",
        "project_install_count": project_install_count,
        "project_install_authority": "immediate-static-revalidation",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
        "python_safe_path": True,
        "setup_python_cache": False,
        "browser_runtime_authority": "hosted-system-chrome-observed-without-automatic-installer",
        "archive_build_authority": "verified-and-matched-before-wheel-builds",
        "documentation_integrity": "required-via-supply-chain",
        "mermaid_render": "required-via-supply-chain",
        "build_provenance_subject": "CI_SUBJECT_SHA/isolated-git-view",
        "archive_attribute_authority": "versioned-tree-only",
        "sbom_lineage": "parent-digest-bound-and-bracketed",
        "supply_chain_evidence": "pinned-upload-action",
        "permissions": "contents:read",
        "status_write_authority": "isolated-generated-maintenance-check-publication",
        "protected_maintenance_authority": "centralized-app-gate-for-governed-bots",
    }


def _verify_codeql_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  push:",
            "    branches: [main]",
            "  pull_request:",
            "    branches: [main]",
            "  schedule:",
            '    - cron: "17 7 * * 2"',
            "  workflow_call:",
            "    inputs:",
            "      subject_sha:",
            "        description: Exact current-main commit a trusted reusable caller analyzes",
            "        required: false",
            "        type: string",
            "  workflow_dispatch:",
            "    inputs:",
            "      subject_sha:",
            "        description: Exact commit the trusted-main CodeQL dispatch analyzes",
            "        required: true",
            "        type: string",
            "      subject_ref:",
            "        description: Exact main, Dependabot Actions, or generated-maintenance branch containing subject_sha",
            "        required: true",
            "        type: string",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError("codeql.yml trigger/input set differs from the reviewed definition")
    if base._top_level_keys(base._top_level_block(text, "on")) != {
        "push",
        "pull_request",
        "schedule",
        "workflow_call",
        "workflow_dispatch",
    }:
        raise ValueError("codeql.yml contains unreviewed trigger authority")
    base._verify_top_level_read_only_permissions(text, name="codeql.yml")
    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "${{ secrets.",
        "contents: write",
        "actions: write",
        "pull-requests: write",
        "statuses: write",
        "packages: write",
        "id-token: write",
        "ubuntu-latest",
        "continue-on-error: true",
    ):
        if forbidden in semantic:
            raise ValueError(f"codeql.yml contains forbidden authority token: {forbidden}")

    ordinary_raw = base._job_block(text, "codeql")
    ordinary = base._semantic_text(ordinary_raw)
    qualified_raw = base._job_block(text, "qualified-codeql")
    qualified = base._semantic_text(qualified_raw)
    publisher_raw = base._job_block(text, "publish-qualified-codeql")
    publisher = base._semantic_text(publisher_raw)

    if semantic.count("checks: write") != 1 or "checks: write" not in publisher:
        raise ValueError(
            "codeql.yml must isolate one checks:write grant to qualification publication"
        )
    if "checks: write" in ordinary or "checks: write" in qualified:
        raise ValueError("codeql analysis jobs must not receive check-publication authority")

    ordinary_required = (
        "    name: CodeQL",
        "    if: >-",
        "      github.event_name != 'workflow_dispatch' &&",
        "      (github.event_name != 'workflow_call' || inputs.subject_sha == '') &&",
        "      (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)",
        "      actions: read",
        "      contents: read",
        "      security-events: write",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 20",
        f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}",
        "          persist-credentials: false",
        "      - name: Acquire verified CodeQL 2.27.0 bundle",
        "        id: codeql-tools",
        "release_api='https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.27.0'",
        "asset_url='https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst'",
        're.fullmatch(r"sha256:[0-9a-f]{64}", digest)',
        'test "$observed_sha" = "$expected_sha"',
        "          tools: ${{ steps.codeql-tools.outputs.path }}",
        "          languages: python",
        "          queries: security-extended",
        "      - name: Analyze",
        "        id: codeql-analyze",
        "          output: ${{ runner.temp }}/codeql-sarif",
        "      - name: Require zero CodeQL findings",
        "          SARIF_DIR: ${{ steps.codeql-analyze.outputs.sarif-output }}",
        '        run: python3 scripts/verify_codeql_sarif.py --directory "$SARIF_DIR"',
    )
    for fragment in ordinary_required:
        if fragment not in ordinary:
            raise ValueError(f"codeql.yml ordinary analysis invariant missing: {fragment}")

    qualified_required = (
        "    name: Exact-Subject CodeQL Analysis",
        "    if: >-",
        "      github.event_name == 'workflow_dispatch' ||",
        "      (github.event_name == 'workflow_call' && inputs.subject_sha != '')",
        "      actions: read",
        "      contents: read",
        "      security-events: write",
        "      - name: Bind trusted-main dispatch to exact analysis subject",
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}",
        "          EXPECTED_SUBJECT_REF: ${{ github.event_name == 'workflow_dispatch' && inputs.subject_ref || 'main' }}",
        "          CALL_EVENT: ${{ github.event_name }}",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'if [ "$CALL_EVENT" = "workflow_dispatch" ]; then',
        'test "$GITHUB_SHA" = "$EXPECTED_SUBJECT_SHA"',
        'test "$CALL_EVENT" = "workflow_call"',
        'live_main_sha="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'test "$live_main_sha" = "$EXPECTED_SUBJECT_SHA"',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$ ]]',
        'live_subject_sha="$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/${EXPECTED_SUBJECT_REF}" --jq .object.sha)"',
        "          ref: ${{ inputs.subject_sha }}",
        'run: test "$(git rev-parse HEAD)" = "$EXPECTED_SUBJECT_SHA"',
        "      - name: Acquire verified CodeQL 2.27.0 bundle",
        "        id: codeql-tools",
        "release_api='https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.27.0'",
        "asset_url='https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst'",
        're.fullmatch(r"sha256:[0-9a-f]{64}", digest)',
        'test "$observed_sha" = "$expected_sha"',
        "          tools: ${{ steps.codeql-tools.outputs.path }}",
        "      - name: Analyze exact bound subject",
        "        id: qualified-codeql-analyze",
        "          ref: refs/heads/${{ github.event_name == 'workflow_dispatch' && inputs.subject_ref || 'main' }}",
        "          sha: ${{ inputs.subject_sha }}",
        "          output: ${{ runner.temp }}/qualified-codeql-sarif",
        "      - name: Require zero exact-subject CodeQL findings",
        "          SARIF_DIR: ${{ steps.qualified-codeql-analyze.outputs.sarif-output }}",
        '        run: python3 scripts/verify_codeql_sarif.py --directory "$SARIF_DIR"',
    )
    for fragment in qualified_required:
        if fragment not in qualified:
            raise ValueError(f"codeql.yml exact-subject analysis invariant missing: {fragment}")

    publisher_required = (
        "    name: Publish Exact-Subject CodeQL",
        "    needs: qualified-codeql",
        "inputs.subject_ref != 'main'",
        "    permissions:\n      checks: write\n      contents: read",
        "repos/${GITHUB_REPOSITORY}/check-runs",
        'external_id="aiqa-codeql-qualification:${EXPECTED_SUBJECT_SHA}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"',
        '{name:"CodeQL",head_sha:$head,status:"completed",conclusion:$conclusion',
        'test "$(jq -r \'.external_id\' <<<"$response")" = "$external_id"',
        'test "$(jq -r \'.head_sha\' <<<"$response")" = "$EXPECTED_SUBJECT_SHA"',
    )
    for fragment in publisher_required:
        if fragment not in publisher:
            raise ValueError(f"codeql.yml exact-subject publication invariant missing: {fragment}")
    if "actions/checkout@" in publisher or "${{ secrets." in publisher:
        raise ValueError(
            "codeql.yml publication must not execute candidate bytes or consume secrets"
        )

    if semantic.count("      - name: Acquire verified CodeQL 2.27.0 bundle") != 2:
        raise ValueError("codeql.yml must acquire one verified local bundle per analysis job")
    if semantic.count("          tools: ${{ steps.codeql-tools.outputs.path }}") != 2:
        raise ValueError("codeql.yml must bind both analyses to verified local bundle paths")
    if semantic.count("verify_codeql_sarif.py --directory") != 2:
        raise ValueError(
            "codeql.yml must enforce the SARIF zero-findings gate in both analysis jobs"
        )

    uses = base.ACTION_RE.findall(text)
    if len(uses) != 6:
        raise ValueError(
            "codeql.yml must contain two checkout, two CodeQL init, and two CodeQL analyze uses"
        )
    checkout = [item for item in uses if item[0] == "actions/checkout"]
    if len(checkout) != 2 or {item[1].lower() for item in checkout} != {
        base.EXPECTED_ACTION_SHAS["actions/checkout"]
    }:
        raise ValueError("codeql.yml checkout actions must use the reviewed immutable revision")
    codeql = CODEQL_ACTION_RE.findall(text)
    if len(codeql) != 4 or {item[0] for item in codeql} != {
        "github/codeql-action/init",
        "github/codeql-action/analyze",
    }:
        raise ValueError("codeql.yml must use two reviewed CodeQL init/analyze pairs")
    codeql_refs = {item[1].lower() for item in codeql}
    codeql_versions = {item[2] for item in codeql}
    if len(codeql_refs) != 1 or len(codeql_versions) != 1:
        raise ValueError("CodeQL init/analyze pairs must share one immutable reviewed revision")
    version = next(iter(codeql_versions))
    if int(version.split(".", 1)[0]) != EXPECTED_CODEQL_MAJOR:
        raise ValueError("CodeQL action major version differs from the reviewed v4 authority")
    if semantic.count("security-events: write") != 2:
        raise ValueError("codeql.yml must isolate security-events write to its two analysis jobs")
    if base._workflow_structure_sha1(text) != EXPECTED_CODEQL_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "codeql.yml non-action structure differs from the reviewed CodeQL definition"
        )

    return {
        "triggers": ["pull_request", "push", "schedule", "workflow_call", "workflow_dispatch"],
        "language": "python",
        "queries": "security-extended",
        "codeql_action_sha": next(iter(codeql_refs)),
        "codeql_major": EXPECTED_CODEQL_MAJOR,
        "codeql_tools_authority": "release-asset-sha256-verified-local-archive",
        "checkout_authority": "exact-reviewed-immutable-sha",
        "security_events_write": True,
        "workflow_dispatch_subject": "trusted-main-plus-explicit-ref-sha",
        "workflow_call_subject": "trusted-caller-plus-exact-current-main-sha",
        "candidate_sarif_binding": "explicit-ref-plus-sha",
        "security_result_gate": "zero-codeql-sarif-findings",
        "candidate_check_publication": "isolated-checks-write-after-exact-ref-revalidation",
        "merge_authority": "none",
        "status_write_authority": "none",
        "workflow_definition": "semantic-reviewed-v4-codeql-contract",
    }


def _verify_dependency_governance_pr_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "dependency-governance-pr.yml"
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  pull_request:",
            "    branches: [main]",
            "    types: [opened, synchronize, reopened, ready_for_review]",
            "    paths:",
            "      - '.github/dependabot.yml'",
            "      - '.github/dependency-governance.json'",
            "      - '.github/dependency-recovery.json'",
            "      - '.github/scripts/dependency_governance.py'",
            "      - '.github/scripts/dependency_trusted_merge.py'",
            "      - '.github/scripts/dependency_user_approval.py'",
            "      - '.github/scripts/dependency_governance_selfcheck.py'",
            "      - '.github/scripts/dependency_lock_compiler.py'",
            "      - '.github/scripts/dependency_promotion.py'",
            "      - '.github/scripts/dependency_recovery.py'",
            "      - '.github/scripts/dependency_recovery_selfcheck.py'",
            "      - '.github/scripts/trusted_qualification.py'",
            "      - '.github/scripts/trusted_status.py'",
            "      - '.github/workflows/dependency-governance.yml'",
            "      - '.github/workflows/dependency-trusted-merge.yml'",
            "      - '.github/workflows/post-merge-ci.yml'",
            "      - '.github/workflows/dependency-governance-pr.yml'",
            "      - '.github/workflows/ci.yml'",
            "      - '.github/workflows/reusable-ci.yml'",
            "      - '.github/workflows/reusable-codeql.yml'",
            "      - '.github/workflows/codeql.yml'",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "pull_request"
    }:
        raise ValueError(
            "dependency-governance-pr.yml must remain exact pull_request-only development evidence"
        )
    base._verify_top_level_read_only_permissions(text, name=name)
    env_block = base._semantic_text(base._top_level_block(text, "env")).strip("\n")
    expected_env = "\n".join(
        (
            "env:",
            '  PYTHONUNBUFFERED: "1"',
            '  PYTHONSAFEPATH: "1"',
            "  PYTHONPATH: .github/scripts",
            '  PIP_DISABLE_PIP_VERSION_CHECK: "1"',
            "  GOVERNANCE_CONFIG: .github/dependency-governance.json",
            "  RECOVERY_CONFIG: .github/dependency-recovery.json",
        )
    )
    if env_block != expected_env:
        raise ValueError(
            "dependency-governance-pr.yml explicit safe import/config environment drifted"
        )
    if base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError("dependency-governance-pr.yml must remain read-only")
    for forbidden in (
        "pull_request_target:",
        "workflow_run:",
        "status:",
        "schedule:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "environment:",
        "${{ secrets.",
        "${{ vars.",
        "${{ github.token }}",
        "GITHUB_TOKEN:",
        "continue-on-error: true",
        "ubuntu-latest",
        "actions/create-github-app-token@",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"dependency-governance-pr.yml contains forbidden authority token: {forbidden}"
            )
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    if (
        "  group: dependency-governance-pr-${{ github.event.pull_request.number }}"
        not in concurrency
        or "  cancel-in-progress: true" not in concurrency
    ):
        raise ValueError("dependency-governance-pr.yml stale-run cancellation contract drifted")
    self_test = base._semantic_text(base._job_block(text, "self-test"))
    required = (
        "    name: governance-self-test",
        "    permissions:\n      contents: read",
        "      - name: Checkout proposed governance code without credentials",
        "          persist-credentials: false",
        "      - name: Compile governance control plane",
        ".github/scripts/dependency_trusted_merge.py",
        ".github/scripts/dependency_user_approval.py",
        "      - name: Validate governance and recovery configuration",
        "      - name: Exercise fail-closed policy self-checks",
        "python .github/scripts/dependency_governance_selfcheck.py",
        "python .github/scripts/dependency_promotion.py --self-test",
        "python .github/scripts/dependency_recovery_selfcheck.py",
    )
    for fragment in required:
        if fragment not in self_test:
            raise ValueError(
                f"dependency-governance-pr.yml missing reviewed self-test invariant: {fragment}"
            )
    if semantic.count("actions/checkout@") != 1 or semantic.count("actions/setup-python@") != 1:
        raise ValueError(
            "dependency-governance-pr.yml must use exactly one reviewed checkout/setup pair"
        )
    if base._workflow_structure_sha1(text) != EXPECTED_DEPENDENCY_GOVERNANCE_PR_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "dependency-governance-pr.yml non-action structure differs from reviewed secret-free definition"
        )
    return {
        "triggers": ["pull_request"],
        "authority": "development-evidence-only",
        "permissions": "contents:read",
        "secrets": "forbidden",  # pragma: allowlist secret
        "mutation": "forbidden",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_post_merge_ci_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "post-merge-ci.yml"
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            "    workflows: [dependency-governance, Security Auto-Heal, Protected Security Remediation — ƳƤ AI QA Automation Framework]",
            "    types: [completed]",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "workflow_run",
    }:
        raise ValueError("post-merge-ci.yml must remain exact governed workflow_run only")
    base._verify_top_level_read_only_permissions(text, name=name)
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    for fragment in (
        "  group: post-merge-ci-${{ github.event_name }}-${{ github.event.workflow_run.id || github.run_id }}",
        "  cancel-in-progress: false",
    ):
        if fragment not in concurrency:
            raise ValueError("post-merge-ci.yml concurrency identity drifted")
    for forbidden in (
        "pull_request:",
        "pull_request_target:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "contents: write",
        "statuses: write",
        "pull-requests: write",
        "actions/create-github-app-token",
        "id-token: write",
        "packages: write",
    ):
        if forbidden in semantic:
            raise ValueError(f"{name}: forbidden authority token: {forbidden}")
    if semantic.count("security-events: write") != 1:
        raise ValueError(
            "post-merge-ci.yml must isolate exactly one security-events write to CodeQL"
        )

    if semantic.count("checks: write") != 0:
        raise ValueError("post-merge-ci.yml must not publish checks")

    bind = base._semantic_text(base._job_block(text, "bind"))
    required_bind = (
        "    name: Bind exact governed main advance",
        "github.event_name == 'workflow_run' &&",
        "      github.event.workflow_run.conclusion == 'success' &&",
        "      github.event.workflow_run.head_repository.full_name == github.repository &&",
        "      github.event.workflow_run.head_branch == 'main' &&",
        "      github.event.workflow_run.head_sha != github.sha",
        "      run_validation: ${{ steps.bind.outputs.run_validation }}",
        "    permissions:\n      actions: read\n      contents: read",
        "          EVENT_NAME: ${{ github.event_name }}",
        "          CONTROL_SHA: ${{ github.event.workflow_run.head_sha }}",
        "          SUBJECT_SHA: ${{ github.sha }}",
        "          UPSTREAM_RUN_ID: ${{ github.event.workflow_run.id }}",
        "          UPSTREAM_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
        "          UPSTREAM_PATH: ${{ github.event.workflow_run.path }}",
        '            test "$EVENT_NAME" = "workflow_run"',
        '            test "$UPSTREAM_RUN_ATTEMPT" -le 20',
        '            case "$UPSTREAM_NAME:$UPSTREAM_PATH" in',
        '"dependency-governance:.github/workflows/dependency-governance.yml"',
        "workflow_run|schedule) ;;",
        '"Security Auto-Heal:.github/workflows/security-autoheal.yml"',
        '"Protected Security Remediation — ƳƤ AI QA Automation Framework:.github/workflows/protected-security-remediation.yml"',
        "workflow_run|schedule) ;;",
        "merge_source_re='^Merge pull request #[1-9][0-9]* from portyu9/(dependabot/|automation/dependency-promotion-)'",
        "merge_source_re='^Merge pull request #[1-9][0-9]* from portyu9/automation/codeql-autoheal-'",
        "merge_source_re='^Merge pull request #[1-9][0-9]* from portyu9/automation/protected-security-remediation-'",
        "merge_author_login='github-actions[bot]'",
        "merge_author_id=41898282",
        "merge_author_login='portyu9-security-remediator[bot]'",
        "merge_author_id=333833782",
        '          test "$UPSTREAM_STATUS" = "completed"',
        '          test "$UPSTREAM_CONCLUSION" = "success"',
        '          test "$UPSTREAM_REPOSITORY" = "$GITHUB_REPOSITORY"',
        '            test "$UPSTREAM_HEAD_REPOSITORY" = "$GITHUB_REPOSITORY"',
        '            if [ "$UPSTREAM_RUN_ATTEMPT" -gt 1 ]; then',
        '              test "$UPSTREAM_NAME:$UPSTREAM_PATH" = "Security Auto-Heal:.github/workflows/security-autoheal.yml"',
        "          fi",
        '          live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        '          test "$live_main" = "$SUBJECT_SHA"',
        '          if [ "$SUBJECT_SHA" = "$CONTROL_SHA" ]; then',
        "            printf 'run_validation=false\\n' >> \"$GITHUB_OUTPUT\"",
        "unrelated_main_merge_re='^Merge pull request #[1-9][0-9]* from [A-Za-z0-9_.-]+/'",
        '          if [ "$EVENT_NAME" = "workflow_run" ] && [ "$UPSTREAM_RUN_ATTEMPT" -gt 1 ]; then',
        "            for prior_attempt in $(seq 1 $((UPSTREAM_RUN_ATTEMPT - 1))); do",
        '              prior_json="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${UPSTREAM_RUN_ID}/attempts/${prior_attempt}")"',
        ".run_attempt == $attempt",
        ".name == $name",
        ".path == $path",
        ".event == $event",
        '.head_branch == "main"',
        ".head_sha == $control",
        ".repository.full_name == $repository",
        ".head_repository.full_name == $repository",
        '.status == "completed"',
        '.conclusion == "failure"',
        "((.updated_at | fromdateiso8601) < ($merge_time | fromdateiso8601))",
        '              prior_jobs="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${UPSTREAM_RUN_ID}/attempts/${prior_attempt}/jobs?per_page=100")"',
        ".total_count == 4",
        'job("plan-codeql-autoheal-routes").conclusion == "success"',
        'job("reconcile-codeql-autoheal").conclusion == "success"',
        'job("Approve exact gated security repair as portyu9").conclusion == "failure"',
        '.name == "Publish exact security owner approval after Trusted PR Gate"',
        'job("Merge exact owner-approved security repair").conclusion == "skipped"',
        '(job("Merge exact owner-approved security repair").steps | length) == 0',
        '                baseline_plan_started="$plan_started"',
        '                baseline_reconcile_started="$reconcile_started"',
        '                test "$plan_started" = "$baseline_plan_started"',
        '                test "$reconcile_started" = "$baseline_reconcile_started"',
        '            current_jobs="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${UPSTREAM_RUN_ID}/attempts/${UPSTREAM_RUN_ATTEMPT}/jobs?per_page=100")"',
        'job("plan-codeql-autoheal-routes").started_at == $plan_started',
        'job("plan-codeql-autoheal-routes").completed_at == $plan_completed',
        'job("reconcile-codeql-autoheal").started_at == $reconcile_started',
        'job("reconcile-codeql-autoheal").completed_at == $reconcile_completed',
        'job("Approve exact gated security repair as portyu9").conclusion == "success"',
        'job("Merge exact owner-approved security repair").conclusion == "success"',
        '((job("Merge exact owner-approved security repair").started_at | fromdateiso8601) <',
        '((job("Merge exact owner-approved security repair").completed_at | fromdateiso8601) >=',
        '--arg unrelated_main_merge_re "$unrelated_main_merge_re"',
        "(.commit.message | test($unrelated_main_merge_re))",
        '--arg merge_source_re "$merge_source_re"',
        '--arg merge_author_login "$merge_author_login"',
        '--argjson merge_author_id "$merge_author_id"',
        ".parents[0].sha == $control",
        ".author.login == $merge_author_login",
        ".author.id == $merge_author_id",
        '.committer.login == "web-flow"',
        ".committer.id == 19864447",
        ".commit.verification.verified == true",
        '.commit.verification.reason == "valid"',
        "(.commit.message | test($merge_source_re))",
        "          printf 'run_validation=true\\n' >> \"$GITHUB_OUTPUT\"",
    )
    if any(fragment not in bind for fragment in required_bind):
        raise ValueError("post-merge-ci.yml exact governed-merge binding drifted")

    validate_ci = base._semantic_text(base._job_block(text, "validate-ci"))
    for fragment in (
        "    name: Validate exact governed main CI",
        "    needs: bind",
        "    if: ${{ needs.bind.outputs.run_validation == 'true' }}",
        "    permissions:\n      contents: read",
        "    uses: ./.github/workflows/reusable-ci.yml",
    ):
        if fragment not in validate_ci:
            raise ValueError(
                "post-merge-ci.yml must call canonical reusable CI with isolated check publication ceiling"
            )

    validate_codeql = base._semantic_text(base._job_block(text, "validate-codeql"))
    for fragment in (
        "    name: Validate exact governed main CodeQL",
        "    needs: bind",
        "    if: ${{ needs.bind.outputs.run_validation == 'true' }}",
        "    permissions:\n      actions: read\n      contents: read\n      security-events: write",
        "    uses: ./.github/workflows/reusable-codeql.yml",
    ):
        if fragment not in validate_codeql:
            raise ValueError(
                "post-merge-ci.yml must isolate CodeQL SARIF authority to canonical reusable CodeQL"
            )

    required = base._semantic_text(base._job_block(text, "required"))
    for fragment in (
        "    name: Post-Merge Required Gate",
        "    needs: [bind, validate-ci, validate-codeql]",
        "    if: ${{ always() && needs.bind.result == 'success' && needs.bind.outputs.run_validation == 'true' }}",
        "    permissions:\n      contents: read",
        "      - name: Require canonical reusable validations to succeed",
        '          test "${{ needs.validate-ci.result }}" = "success"',
        '          test "${{ needs.validate-codeql.result }}" = "success"',
    ):
        if fragment not in required:
            raise ValueError(
                "post-merge-ci.yml terminal gate differs from reviewed fail-closed contract"
            )

    if base._workflow_structure_sha1(text) != EXPECTED_POST_MERGE_CI_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "post-merge-ci.yml non-action structure differs from the reviewed post-merge definition"
        )
    return {
        "trigger": "workflow_run:dependency-governance-or-security-autoheal-or-protected-security-remediation:completed",
        "authority": "exact-governed-main-validation-plus-isolated-check-and-codeql-sarif-write",
        "subject": "single-signed-lane-bound-controller-merge-child-with-replay-safe-security-approval-retry-proof",
        "canonical_ci": "reusable-ci.yml",
        "canonical_codeql": "reusable-codeql.yml",
        "security_events_write": "isolated-codeql-only",
        "checks_write": "none",
        "merge_authority": "none",
        "trusted_status_authority": "none",
    }



def _verify_reusable_ci_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    on_block = base._semantic_text(base._top_level_block(text, "on"))
    if base._top_level_keys(base._top_level_block(text, "on")) != {"workflow_call"}:
        raise ValueError("reusable-ci.yml must remain workflow_call only")
    for fragment in (
        "      subject_sha:",
        "        required: true",
        "        type: string",
    ):
        if fragment not in on_block:
            raise ValueError("reusable-ci.yml exact subject input drifted")
    base._verify_top_level_read_only_permissions(text, name="reusable-ci.yml")
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {
        "quality", "deterministic-evals", "supply-chain", "security",
        "browser-reference-sut", "required-gate",
    }:
        raise ValueError("reusable-ci.yml job set drifted")
    for forbidden in (
        "workflow_dispatch:", "repository_dispatch:", "pull_request:",
        "pull_request_target:", "push:", "merge_group:", "schedule:",
        "checks: write", "contents: write", "actions: write",
        "security-events: write", "pull-requests: write", "statuses: write",
        "id-token: write", "packages: write", "${{ secrets.",
        "continue-on-error: true", "ubuntu-latest",
    ):
        if forbidden in semantic:
            raise ValueError(f"reusable-ci.yml contains forbidden authority token: {forbidden}")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    if (
        "  group: ai-qa-reusable-ci-${{ inputs.subject_sha }}" not in concurrency
        or "  cancel-in-progress: true" not in concurrency
    ):
        raise ValueError("reusable-ci.yml concurrency drifted")
    env_block = base._semantic_text(base._top_level_block(text, "env"))
    if "  CI_SUBJECT_SHA: ${{ inputs.subject_sha }}" not in env_block:
        raise ValueError("reusable-ci.yml top-level subject binding drifted")

    checkout_count = _verify_ordinary_checkout_binding(text)
    dependency_install_count = base._verify_dependency_install_authority(text, name="reusable-ci.yml")
    project_install_count = base._verify_project_install_authority(text, name="reusable-ci.yml")
    quality_lanes = base._verify_quality_lane_contract(text, name="reusable-ci.yml")
    for job_id in ("supply-chain", "quality", "deterministic-evals", "security", "browser-reference-sut"):
        job = base._semantic_text(base._job_block(text, job_id))
        if "      CI_SUBJECT_SHA: ${{ inputs.subject_sha }}" not in job:
            raise ValueError(f"reusable-ci.yml {job_id} lost exact subject binding")

    supply_raw = base._job_block(text, "supply-chain")
    supply = base._semantic_text(supply_raw)
    for fragment in (
        "      - name: Bind trusted reusable call to exact current main",
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}",
        '[[ "$EXPECTED_SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        'test "$GITHUB_REF" = "refs/heads/main"',
        'live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'test "$live_main" = "$EXPECTED_SUBJECT_SHA"',
    ):
        if fragment not in supply:
            raise ValueError("reusable-ci.yml current-main binding drifted")
    if "Bind trusted-main dispatch to exact approved subject" in supply:
        raise ValueError("reusable-ci.yml retained dispatch-only binding")

    base._require_exact_build_authority_step(supply_raw)
    base._require_exact_verification_install_step(supply_raw)
    base._require_exact_script_step(
        supply_raw, step_name=base.DOCUMENTATION_STEP_NAME, command=base.DOCUMENTATION_INTEGRITY_COMMAND
    )
    base._require_exact_script_step(
        supply_raw, step_name=base.MERMAID_STEP_NAME, command=base.MERMAID_RENDER_COMMAND
    )
    base._require_exact_runtime_sbom_step(supply_raw)
    base._require_exact_reproducible_build_step(supply_raw)
    base._require_exact_supply_chain_upload_step(supply_raw)
    base._require_exact_hosted_browser_step(base._job_block(text, "browser-reference-sut"))
    required_raw = base._job_block(text, "required-gate")
    required = base._semantic_text(required_raw)
    if "    name: Required PR Gate" not in required or "    if: ${{ always() }}" not in required:
        raise ValueError("reusable-ci.yml required gate drifted")
    base._require_exact_required_gate_step(required_raw)
    for job in base.AUTOMATIC_REQUIRED_JOBS:
        if f"      - {job}\n" not in required:
            raise ValueError(f"reusable-ci.yml Required PR Gate does not depend on {job}")
    return {
        "trigger": "workflow_call",
        "subject": "required-exact-current-main-sha",
        "checkout_count": checkout_count,
        "quality_lanes": quality_lanes,
        "dependency_install_count": dependency_install_count,
        "project_install_count": project_install_count,
        "checks_write": "none",
    }


def _verify_reusable_codeql_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    on_block = base._semantic_text(base._top_level_block(text, "on"))
    if base._top_level_keys(base._top_level_block(text, "on")) != {"workflow_call"}:
        raise ValueError("reusable-codeql.yml must remain workflow_call only")
    for fragment in ("      subject_sha:", "        required: true", "        type: string"):
        if fragment not in on_block:
            raise ValueError("reusable-codeql.yml exact subject input drifted")
    base._verify_top_level_read_only_permissions(text, name="reusable-codeql.yml")
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {"qualified-codeql"}:
        raise ValueError("reusable-codeql.yml must expose one analysis job")
    for forbidden in (
        "workflow_dispatch:", "repository_dispatch:", "pull_request:",
        "pull_request_target:", "push:", "schedule:", "checks: write",
        "contents: write", "actions: write", "pull-requests: write",
        "statuses: write", "id-token: write", "packages: write",
        "${{ secrets.", "continue-on-error: true", "ubuntu-latest",
    ):
        if forbidden in semantic:
            raise ValueError(f"reusable-codeql.yml contains forbidden authority token: {forbidden}")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    if (
        "  group: ai-qa-reusable-codeql-${{ inputs.subject_sha }}" not in concurrency
        or "  cancel-in-progress: true" not in concurrency
    ):
        raise ValueError("reusable-codeql.yml concurrency drifted")
    job = base._semantic_text(base._job_block(text, "qualified-codeql"))
    if _trusted_auto._job_permissions(job) != {
        "actions": "read", "contents": "read", "security-events": "write"
    }:
        raise ValueError("reusable-codeql.yml SARIF permission ceiling drifted")
    if semantic.count("security-events: write") != 1:
        raise ValueError("reusable-codeql.yml must isolate exactly one SARIF write")
    for fragment in (
        "    name: Exact-Subject CodeQL Analysis",
        "    if: ${{ inputs.subject_sha != '' }}",
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}",
        "          EXPECTED_SUBJECT_REF: main",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'live_main_sha="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'test "$live_main_sha" = "$EXPECTED_SUBJECT_SHA"',
        "          ref: ${{ inputs.subject_sha }}",
        'run: test "$(git rev-parse HEAD)" = "$EXPECTED_SUBJECT_SHA"',
        "      - name: Acquire verified CodeQL 2.27.0 bundle",
        "          tools: ${{ steps.codeql-tools.outputs.path }}",
        "      - name: Analyze exact bound subject",
        "          ref: refs/heads/main",
        "          sha: ${{ inputs.subject_sha }}",
        "      - name: Require zero exact-subject CodeQL findings",
        'verify_codeql_sarif.py --directory "$SARIF_DIR"',
    ):
        if fragment not in job:
            raise ValueError(f"reusable-codeql.yml invariant missing: {fragment}")
    uses = base.ACTION_RE.findall(text)
    if len(uses) != 3:
        raise ValueError("reusable-codeql.yml must contain one checkout/init/analyze action set")
    checkout = [item for item in uses if item[0] == "actions/checkout"]
    if len(checkout) != 1 or checkout[0][1].lower() != base.EXPECTED_ACTION_SHAS["actions/checkout"]:
        raise ValueError("reusable-codeql.yml checkout action pin drifted")
    codeql = CODEQL_ACTION_RE.findall(text)
    if len(codeql) != 2 or {item[0] for item in codeql} != {
        "github/codeql-action/init", "github/codeql-action/analyze"
    }:
        raise ValueError("reusable-codeql.yml CodeQL action set drifted")
    codeql_refs = {item[1].lower() for item in codeql}
    codeql_versions = {item[2] for item in codeql}
    if len(codeql_refs) != 1 or len(codeql_versions) != 1:
        raise ValueError("reusable-codeql.yml CodeQL pin/version drifted")
    if int(next(iter(codeql_versions)).split(".", 1)[0]) != EXPECTED_CODEQL_MAJOR:
        raise ValueError("reusable-codeql.yml CodeQL major drifted")
    return {
        "trigger": "workflow_call",
        "subject": "required-exact-current-main-sha",
        "security_events_write": "one-analysis-job-only",
        "checks_write": "none",
    }

def _verify_dependency_trusted_merge_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    name = "dependency-trusted-merge.yml"
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            '    workflows: ["Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"]',
            "    types: [completed]",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "workflow_run"
    }:
        raise ValueError(
            "dependency-trusted-merge.yml must remain Trusted PR Auto Gate workflow_run only"
        )
    base._verify_top_level_read_only_permissions(text, name=name)
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {
        "resolve",
        "approve",
        "merge",
        "cleanup-promotion-branch",
        "post-merge-ci",
        "post-merge-codeql",
        "post-merge-required",
    }:
        raise ValueError(
            "dependency-trusted-merge.yml must expose only reviewed resolution, approval, "
            "merge, cleanup, same-run validation, and terminal-evidence jobs"
        )
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    for fragment in (
        "  group: dependency-trusted-merge-global-reconcile",
        "  cancel-in-progress: false",
    ):
        if fragment not in concurrency:
            raise ValueError("dependency trusted merge concurrency contract drifted")

    for forbidden in (
        "pull_request:",
        "pull_request_target:",
        "push:",
        "schedule:",
        "\n  status:",
        "issue_comment:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "continue-on-error: true",
        "ubuntu-latest",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "PROTECTED_REMEDIATION_APP_PRIVATE_KEY",
        "actions/create-github-app-token@",
        "statuses: write",
        "actions: write",
        "id-token: write",
        "packages: write",
        "PROMOTION_AUTHOR_TOKEN",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"dependency-trusted-merge.yml contains forbidden authority token: {forbidden}"
            )

    resolve_job = base._semantic_text(base._job_block(text, "resolve"))
    approve_job = base._semantic_text(base._job_block(text, "approve"))
    merge_job = base._semantic_text(base._job_block(text, "merge"))
    cleanup_job = base._semantic_text(base._job_block(text, "cleanup-promotion-branch"))
    post_merge_ci = base._semantic_text(base._job_block(text, "post-merge-ci"))
    post_merge_codeql = base._semantic_text(base._job_block(text, "post-merge-codeql"))
    post_merge_required = base._semantic_text(base._job_block(text, "post-merge-required"))
    if _trusted_auto._job_permissions(resolve_job) != {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
        "statuses": "read",
    }:
        raise ValueError("dependency trusted target resolver must remain job-level read-only")
    if (
        "    environment:" in resolve_job
        or "contents: write" in resolve_job
        or "pull-requests: write" in resolve_job
        or re.search(r"\\bsecrets\\b", resolve_job) is not None
    ):
        raise ValueError("dependency trusted target resolver gained mutation or secret authority")
    if _trusted_auto._job_permissions(approve_job) != {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
        "statuses": "read",
    }:
        raise ValueError("dependency owner approval job must remain workflow-token read-only")
    if "contents: write" in approve_job or "pull-requests: write" in approve_job:
        raise ValueError("dependency owner approval job gained workflow-token write authority")
    owner_secret_expressions = re.findall(
        r"\$\{\{[^}]*\bsecrets\b[^}]*\}\}",
        semantic,
    )
    if owner_secret_expressions != ["${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}"]:
        raise ValueError(
            "dependency trusted merge owner-review secret inventory drifted from one exact credential"
        )
    owner_review_secret_binding = "PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}"  # pragma: allowlist secret
    if (
        "    environment:\n      name: portyu9-review-identity\n      deployment: false"
        not in approve_job
        or owner_review_secret_binding not in approve_job
    ):
        raise ValueError("dependency owner review credential escaped its isolated environment job")
    if _trusted_auto._job_permissions(merge_job) != {
        "actions": "read",
        "contents": "write",
        "pull-requests": "write",
        "statuses": "read",
    }:
        raise ValueError(
            "dependency trusted merge job permission ceiling drifted from exact target-only authority"
        )
    if re.search(r"\bsecrets\b", merge_job) is not None:
        raise ValueError("dependency trusted merger gained owner-review or secret authority")
    if semantic.count("contents: write") != 2 or semantic.count("pull-requests: write") != 1:
        raise ValueError(
            "dependency trusted merge must isolate one merge write ceiling and one exact-ref cleanup ceiling"
        )
    if semantic.count("checks: write") != 1:
        raise ValueError(
            "dependency trusted merge must isolate check publication to terminal evidence"
        )
    if semantic.count("security-events: write") != 1:
        raise ValueError(
            "dependency trusted merge must isolate one reusable CodeQL SARIF write ceiling"
        )
    if _trusted_auto._job_permissions(cleanup_job) != {
        "contents": "write",
        "pull-requests": "read",
    }:
        raise ValueError("dependency promotion cleanup permission ceiling drifted")
    if _trusted_auto._job_permissions(post_merge_ci) != {
        "contents": "read",
    }:
        raise ValueError("dependency post-merge reusable CI permission ceiling drifted")
    if _trusted_auto._job_permissions(post_merge_codeql) != {
        "actions": "read",
        "contents": "read",
        "security-events": "write",
    }:
        raise ValueError("dependency post-merge reusable CodeQL permission ceiling drifted")
    if _trusted_auto._job_permissions(post_merge_required) != {
        "checks": "write",
        "contents": "read",
        "pull-requests": "read",
    }:
        raise ValueError("dependency terminal evidence permission ceiling drifted")
    if any(
        re.search(r"\bsecrets\b", job) is not None
        for job in (
            cleanup_job,
            post_merge_ci,
            post_merge_codeql,
            post_merge_required,
        )
    ):
        raise ValueError("dependency post-merge jobs gained secret authority")
    if semantic.count("    environment:") != 2:
        raise ValueError(
            "dependency trusted merge must expose exactly owner-review and merger environments"
        )
    if (
        "    environment:\n      name: portyu9-review-identity\n      deployment: false"
        not in approve_job
        or "    environment:\n      name: protected-remediation-author\n      deployment: false"
        not in merge_job
    ):
        raise ValueError("dependency trusted merge environment authority boundaries drifted")

    exact_resolver_outputs = (
        "    outputs:\n"
        "      lane: ${{ steps.target.outputs.lane }}\n"
        "      pr_number: ${{ steps.target.outputs.pr_number }}\n"
        "    steps:"
    )
    if exact_resolver_outputs not in resolve_job:
        raise ValueError(
            "dependency-trusted-merge.yml non-action structure differs from reviewed one-way authority: "
            "resolver outputs must be exactly lane and pr_number"
        )

    resolve_required = (
        "    name: Resolve exact trusted dependency subject",
        "      github.event.workflow_run.conclusion == 'success' &&",
        "      github.event.workflow_run.head_repository.full_name == github.repository &&",
        "(github.event.workflow_run.event == 'workflow_run' ||",
        "github.event.workflow_run.event == 'schedule') &&",
        "      github.event.workflow_run.head_branch == 'main' &&",
        "      github.event.workflow_run.head_sha == github.sha",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}",
        "    outputs:\n      lane: ${{ steps.target.outputs.lane }}\n"
        "      pr_number: ${{ steps.target.outputs.pr_number }}",
        "      - name: Checkout exact trusted default-branch resolver",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        "          fetch-depth: 1",
        "      - name: Set up resolver Python 3.11",
        "          python-version: '3.11.16'",
        "      - name: Verify exact accepted-main resolver revision",
        '          test "$GITHUB_REF" = "refs/heads/main"',
        '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "      - name: Resolve exact dependency subject from completed Trusted PR Gate",
        "        id: target",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "          PROTECTED_REMEDIATION_BOT_ID: ${{ vars.PROTECTED_REMEDIATION_BOT_ID }}",
        "          python .github/scripts/dependency_trusted_merge.py",
        '          --trusted-run-id "${{ github.event.workflow_run.id }}"',
        '            --trusted-run-attempt "${{ github.event.workflow_run.run_attempt }}"',
        "          set -euo pipefail",
    )
    for fragment in resolve_required:
        if fragment not in resolve_job:
            raise ValueError(
                f"dependency trusted resolver missing reviewed authority invariant: {fragment}"
            )
    resolve_step = base._semantic_text(
        base._step_block(
            resolve_job, "Resolve exact dependency subject from completed Trusted PR Gate"
        )
    )
    if (
        "--github-output" in resolve_step
        or '3>> "$GITHUB_OUTPUT"' not in resolve_step
        or '>> "$GITHUB_OUTPUT"' in resolve_step.replace('3>> "$GITHUB_OUTPUT"', "")
    ):
        raise ValueError(
            "trusted dependency target resolution must use only inherited fd 3 for runner output"
        )

    approve_required = (
        "    name: Approve exact trusted dependency subject as portyu9",
        "    needs: resolve",
        "      needs.resolve.result == 'success' &&",
        "      needs.resolve.outputs.pr_number != '' &&",
        "(needs.resolve.outputs.lane == 'dependency-promotion' ||",
        "needs.resolve.outputs.lane == 'dependabot-actions')",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    environment:\n      name: portyu9-review-identity\n      deployment: false",
        "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}",
        "      - name: Checkout exact trusted owner-review controller",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        "          fetch-depth: 1",
        "      - name: Set up owner-review Python 3.11",
        "          python-version: '3.11.16'",
        "      - name: Verify exact accepted-main owner-review controller revision",
        '          test "$GITHUB_REF" = "refs/heads/main"',
        '          test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "      - name: Publish exact owner approval after Trusted PR Gate",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
        "          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "          PROTECTED_REMEDIATION_BOT_ID: ${{ vars.PROTECTED_REMEDIATION_BOT_ID }}",
        "          python .github/scripts/dependency_user_approval.py",
        '          --lane "${{ needs.resolve.outputs.lane }}"',
        '          --pr-number "${{ needs.resolve.outputs.pr_number }}"',
        '          --trusted-run-id "${{ github.event.workflow_run.id }}"',
        '          --trusted-run-attempt "${{ github.event.workflow_run.run_attempt }}"',
    )
    for fragment in approve_required:
        if fragment not in approve_job:
            raise ValueError(
                f"dependency owner approval missing reviewed authority invariant: {fragment}"
            )

    merge_required = (
        "    name: Merge exact trusted dependency subject",
        "    needs: [resolve, approve]",
        "      needs.resolve.result == 'success' &&",
        "      needs.approve.result == 'success' &&",
        "      needs.resolve.outputs.pr_number != '' &&",
        "(needs.resolve.outputs.lane == 'dependency-promotion' ||",
        "needs.resolve.outputs.lane == 'dependabot-actions')",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 20",
        "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}",
        "    outputs:\n"
        "      control_sha: ${{ steps.post_merge_subject.outputs.control_sha }}\n"
        "      subject_sha: ${{ steps.post_merge_subject.outputs.subject_sha }}",
        "      - name: Checkout exact trusted default-branch merge controller",
        "      - name: Verify exact accepted-main merge controller revision",
        "      - name: Validate resolved dependency mutation target",
        "          TARGET_LANE: ${{ needs.resolve.outputs.lane }}",
        "          TARGET_PR: ${{ needs.resolve.outputs.pr_number }}",
        '          [[ "$TARGET_PR" =~ ^[1-9][0-9]*$ ]]',
        '          case "$TARGET_LANE" in',
        "            dependency-promotion|dependabot-actions) ;;",
        "      - name: Require accepted-main dependency validation before mutation",
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
        "      - name: Capture Python 3.11 resolver",
        "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true' && needs.resolve.outputs.lane == 'dependency-promotion'",
        "      - name: Set up Python 3.14",
        "          python-version: '3.14.7'",
        "      - name: Capture Python 3.14 resolver",
        "      - name: Merge exact trusted dependency promotion",
        "          python .github/scripts/dependency_promotion.py",
        '          --target-promotion-pr "${{ needs.resolve.outputs.pr_number }}"',
        "      - name: Merge exact trusted Dependabot Actions subject",
        "          python .github/scripts/dependency_governance.py",
        '          --target-dependabot-pr "${{ needs.resolve.outputs.pr_number }}"',
        "      - name: Bind exact accepted-main post-merge validation subject",
        "        id: post_merge_subject",
        "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'",
        "          GH_TOKEN: ${{ github.token }}",
        "          CONTROL_SHA: ${{ github.sha }}",
        "          TARGET_LANE: ${{ needs.resolve.outputs.lane }}",
        "          TARGET_PR: ${{ needs.resolve.outputs.pr_number }}",
        '          test "$(jq -r \'.merged\' <<<"$pr_json")" = "true"',
        ".parents[0].sha == $control",
        ".parents[1].sha == $head",
        '.author.login == "github-actions[bot]"',
        ".author.id == 41898282",
        '.committer.login == "web-flow"',
        ".committer.id == 19864447",
        ".commit.verification.verified == true",
        '.commit.verification.reason == "valid"',
        '          printf \'control_sha=%s\\n\' "$CONTROL_SHA" >> "$GITHUB_OUTPUT"',
        '          printf \'subject_sha=%s\\n\' "$subject_sha" >> "$GITHUB_OUTPUT"',
    )
    for fragment in merge_required:
        if fragment not in merge_job:
            raise ValueError(
                f"dependency trusted merger missing reviewed authority invariant: {fragment}"
            )
    post_merge_required_fragments = (
        "    name: Delete consumed dependency promotion branch",
        "    needs: [resolve, approve, merge]",
        "      needs.resolve.outputs.lane == 'dependency-promotion' &&",
        "    permissions:\n      contents: write\n      pull-requests: read",
        "      - name: Delete exact consumed promotion head",
        "          --cleanup-merged-promotion",
        '          --target-promotion-pr "${{ needs.resolve.outputs.pr_number }}"',
        '          --expected-control-sha "${{ needs.merge.outputs.control_sha }}"',
        '          --expected-subject-sha "${{ needs.merge.outputs.subject_sha }}"',
        "    name: Validate exact merged dependency CI",
        "    uses: ./.github/workflows/reusable-ci.yml",
        "      subject_sha: ${{ needs.merge.outputs.subject_sha }}",
        "    name: Validate exact merged dependency CodeQL",
        "    uses: ./.github/workflows/reusable-codeql.yml",
        "      security-events: write",
        "    name: Dependency Post-Merge Required Gate",
        "      always() &&",
        "      - name: Reprove exact merge and publish terminal post-merge evidence",
        '          test "$GITHUB_RUN_ATTEMPT" = "1"',
        '          test "$CI_RESULT" = "success"',
        '          test "$CODEQL_RESULT" = "success"',
        '              test "$CLEANUP_RESULT" = "success"',
        '              test "$CLEANUP_RESULT" = "skipped"',
        'external_id="aiqa-dependency-post-merge-v1:${TARGET_PR}:${CONTROL_SHA}:${SUBJECT_SHA}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"',
        "          jq -e '.total_count <= 100 and (.check_runs | length) == .total_count' <<<\"$existing\" >/dev/null",
        '{name:"Dependency Post-Merge Gate",head_sha:$head,status:"completed",conclusion:"success"',
        ".app.id == 15368",
        '.app.slug == "github-actions"',
    )
    for fragment in post_merge_required_fragments:
        if fragment not in semantic:
            raise ValueError(
                f"dependency post-merge same-run authority invariant missing: {fragment}"
            )

    if semantic.count("actions/checkout@") != 4 or semantic.count("actions/setup-python@") != 5:
        raise ValueError(
            "dependency trusted merge must use four exact checkouts and five exact Python setups"
        )
    promotion = base._semantic_text(
        base._step_block(merge_job, "Merge exact trusted dependency promotion")
    )
    actions = base._semantic_text(
        base._step_block(merge_job, "Merge exact trusted Dependabot Actions subject")
    )
    for step, lane in (
        (promotion, "dependency-promotion"),
        (actions, "dependabot-actions"),
    ):
        required_guard = (
            "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true' && "
            f"needs.resolve.outputs.lane == '{lane}'"
        )
        if required_guard not in step:
            raise ValueError("dependency trusted merge lane-to-target mutation binding drifted")
        if "          GITHUB_TOKEN: ${{ github.token }}" not in step:
            raise ValueError("dependency trusted merge mutation lacks exact native token binding")

    validate_index = merge_job.index("      - name: Validate resolved dependency mutation target")
    barrier_index = merge_job.index(
        "      - name: Require accepted-main dependency validation before mutation"
    )
    promotion_index = merge_job.index("      - name: Merge exact trusted dependency promotion")
    actions_index = merge_job.index("      - name: Merge exact trusted Dependabot Actions subject")
    bind_index = merge_job.index(
        "      - name: Bind exact accepted-main post-merge validation subject"
    )
    if not validate_index < barrier_index < promotion_index < actions_index < bind_index:
        raise ValueError(
            "dependency post-merge barrier, target validation, merge, and subject binding are out of reviewed order"
        )

    observed_structure_sha = base._workflow_structure_sha1(text)
    if observed_structure_sha != EXPECTED_DEPENDENCY_TRUSTED_MERGE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "dependency-trusted-merge.yml non-action structure differs from reviewed one-way "
            f"authority: expected={EXPECTED_DEPENDENCY_TRUSTED_MERGE_WORKFLOW_BLOB_SHA} "
            f"observed={observed_structure_sha}"
        )
    return {
        "trigger": "workflow_run:trusted-pr-auto:completed",
        "trusted_code_source": "accepted-main-only",
        "upstream_authority": "exact-successful-trusted-gate-run-only",
        "target_cardinality": "zero-or-one-exact-gate-bound-dependency-subject",
        "resolver_authority": "separate-read-only-job",
        "owner_review_authority": "isolated-portyu9-identity-after-exact-app-gate",
        "owner_review_secret": "one-environment-scoped-portyu9-review-token",  # pragma: allowlist secret
        "merge_authority": "separate-existing-exact-target-mergers-only",
        "promotion_cleanup": "isolated-exact-consumed-ref-delete-required-for-terminal-success",
        "post_merge_validation": "same-run-reusable-ci-plus-codeql",
        "terminal_evidence": "first-attempt-exact-github-actions-check-bound-to-pr-control-subject-run",
        "branch_or_pr_creation_authority": "none",
        "trusted_status_authority": "none",
        "app_credential_authority": "none",
        "feedback_loop": "forbidden-trusted-gate-does-not-listen-to-this-workflow",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_dependency_governance_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            "    workflows: [CodeQL]",
            "    types: [completed]",
            "    branches:",
            "      - main",
            "      - 'dependabot/github_actions/**'",
            "      - 'dependabot/pip/**'",
            "      - 'automation/dependency-promotion-*'",
            "  schedule:",
            "    - cron: '*/5 * * * *'",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "workflow_run",
        "schedule",
    }:
        raise ValueError(
            "dependency-governance.yml must remain accepted-main workflow_run/schedule only"
        )
    for forbidden_trigger in (
        "pull_request:",
        "pull_request_target:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "  status:",
        "--recover-post-merge",
        "--await-trusted-status-event",
        "status-sync:",
        "status-merge:",
    ):
        if forbidden_trigger in semantic:
            raise ValueError(
                f"dependency-governance.yml contains forbidden trigger/legacy wake: {forbidden_trigger}"
            )

    base._verify_top_level_read_only_permissions(text, name="dependency-governance.yml")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    for fragment in (
        "  group: dependency-governance-global-reconcile",
        "  cancel-in-progress: false",
    ):
        if fragment not in concurrency:
            raise ValueError(
                "dependency-governance.yml reconciliation concurrency contract drifted"
            )

    jobs = base._top_level_keys(base._top_level_block(text, "jobs"))
    expected_jobs = {
        "post-merge-state",
        "validate-post-merge-ci",
        "validate-post-merge-codeql",
        "post-merge-required",
        "govern",
    }
    if jobs != expected_jobs:
        raise ValueError(
            "dependency-governance.yml job set differs from reviewed schedule-owned post-merge authority"
        )

    state_job = base._semantic_text(base._job_block(text, "post-merge-state"))
    validate_ci = base._semantic_text(base._job_block(text, "validate-post-merge-ci"))
    validate_codeql = base._semantic_text(base._job_block(text, "validate-post-merge-codeql"))
    required_job = base._semantic_text(base._job_block(text, "post-merge-required"))
    govern_job = base._semantic_text(base._job_block(text, "govern"))

    if _trusted_auto._job_permissions(state_job) != {
        "actions": "read",
        "contents": "read",
        "pull-requests": "read",
    }:
        raise ValueError("dependency post-merge state inspection must remain read-only")
    if "    environment:" in state_job or re.search(r"\\bsecrets\\b", state_job) is not None:
        raise ValueError(
            "dependency post-merge state inspection gained secret/environment authority"
        )
    for fragment in (
        "    name: Inspect exact dependency post-merge state",
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n"
        "        startsWith(github.event.workflow_run.head_branch, "
        "'automation/dependency-promotion-')))",
        "    timeout-minutes: 5",
        "      current: ${{ steps.revision.outputs.current }}",
        "      mutation_ready: ${{ steps.state.outputs.mutation_ready }}",
        "      post_merge_state: ${{ steps.state.outputs.post_merge_state }}",
        "      subject_sha: ${{ steps.state.outputs.subject_sha }}",
        "      control_sha: ${{ steps.state.outputs.control_sha }}",
        "      - name: Checkout exact trusted default-branch recovery revision",
        "          ref: ${{ github.sha }}",
        "      - name: Verify exact current-main recovery revision",
        "        id: revision",
        "      - name: Validate read-only dependency recovery policy",
        "      - name: Inspect exact accepted-main dependency validation state",
        "        id: state",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in state_job:
            raise ValueError("dependency post-merge state inspection drifted")

    if _trusted_auto._job_permissions(validate_ci) != {
        "contents": "read",
    }:
        raise ValueError("dependency post-merge reusable CI permission ceiling drifted")
    if _trusted_auto._job_permissions(validate_codeql) != {
        "actions": "read",
        "contents": "read",
        "security-events": "write",
    }:
        raise ValueError("dependency post-merge reusable CodeQL permission ceiling drifted")
    for reusable in (validate_ci, validate_codeql):
        for fragment in (
            "    needs: post-merge-state",
            "needs.post-merge-state.outputs.current == 'true'",
            "needs.post-merge-state.outputs.post_merge_state == 'missing'",
            "github.event_name == 'schedule'",
        ):
            if fragment not in reusable:
                raise ValueError("dependency post-merge reusable validation lost schedule guard")
    if "    uses: ./.github/workflows/reusable-ci.yml" not in validate_ci:
        raise ValueError("dependency post-merge CI must use canonical reusable CI")
    if "    uses: ./.github/workflows/reusable-codeql.yml" not in validate_codeql:
        raise ValueError("dependency post-merge CodeQL must use canonical reusable CodeQL")

    if _trusted_auto._job_permissions(required_job) != {"contents": "read"}:
        raise ValueError("dependency post-merge terminal gate must remain read-only")
    for fragment in (
        "    name: Dependency Post-Merge Required Gate",
        "    needs: [post-merge-state, validate-post-merge-ci, validate-post-merge-codeql]",
        "      always() &&",
        "      needs.post-merge-state.outputs.post_merge_state == 'missing' &&",
        "      github.event_name == 'schedule'",
        "      - name: Require owner-scheduled exact-main reusable validation",
        '          test "$GITHUB_EVENT_NAME" = "schedule"',
        '          test "$GITHUB_ACTOR" = "portyu9"',
        '          test "${{ github.triggering_actor }}" = "portyu9"',
        '          test "$EXPECTED_SUBJECT_SHA" = "$GITHUB_SHA"',
        '          test "$CI_RESULT" = "success"',
        '          test "$CODEQL_RESULT" = "success"',
        '          test "$live_main" = "$EXPECTED_SUBJECT_SHA"',
    ):
        if fragment not in required_job:
            raise ValueError("dependency post-merge terminal gate drifted")

    if _trusted_auto._job_permissions(govern_job) != {
        "actions": "write",
        "checks": "write",
        "contents": "write",
        "pull-requests": "write",
        "statuses": "read",
    }:
        raise ValueError("dependency governance mutation permission ceiling drifted")
    if (
        "    environment:\n      name: protected-remediation-author\n      deployment: false"
        not in govern_job
    ):
        raise ValueError("dependency governance mutation environment drifted")
    for fragment in (
        "      - post-merge-state",
        "      - validate-post-merge-ci",
        "      - validate-post-merge-codeql",
        "      - post-merge-required",
        "      always() &&",
        "needs.post-merge-state.outputs.mutation_ready == 'true'",
        "needs.post-merge-required.result == 'success'",
        "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}",
        "      - name: Verify exact current-main governance revision before mutation",
        'live=g._live_main_sha(api, config); expected=os.environ["GITHUB_SHA"]; '
        'print("true" if live == expected else "false")',
        '          test "$current" = "true"',
        "      - name: Validate trusted governance and recovery policy",
        "      - name: Admit exact dependency post-merge validation before mutation",
        "        id: post_merge_admission",
        '          if [ "$PREVIOUS_READY" = "true" ]; then',
        "              --check-post-merge",
        '          elif [ "$GITHUB_EVENT_NAME" = "schedule" ] && [ "$PREVIOUS_STATE" = "missing" ]; then',
        '            test "$SAME_RUN_CI" = "success"',
        '            test "$SAME_RUN_CODEQL" = "success"',
        '            test "$SAME_RUN_GATE" = "success"',
        "          printf 'mutation_ready=true\\n' >> \"$GITHUB_OUTPUT\"",
        "      - name: Attempt one bounded transient recovery",
        "steps.post_merge_admission.outputs.mutation_ready == 'true'",
        "      - name: Validate independent promotion author identity configuration",
        "      - name: Mint independent promotion author token",
        f"        uses: actions/create-github-app-token@{EXPECTED_PROTECTED_AUTHOR_ACTION_SHA} # v3.2.0",
        "          permission-contents: write",
        "          permission-pull-requests: write",
        "      - name: Bind promotion author token to reviewed bot identity",
        "      - name: Reconcile exact-subject Python dependency promotion",
        "      - name: Reconcile Dependabot action merge authority",
        "printf 'PROMOTION_PYTHON311=%s\\n'",
        "printf 'PROMOTION_PYTHON314=%s\\n'",
    ):
        if fragment not in govern_job:
            raise ValueError("dependency governance schedule-owned mutation admission drifted")

    for forbidden in (
        "ubuntu-latest",
        "continue-on-error: true",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "TRUSTED_STATUS_TOKEN",
        "statuses: write",
        "environment:\n      name: trusted-pr-gate",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"dependency-governance.yml contains forbidden authority token: {forbidden}"
            )

    if semantic.count("actions/create-github-app-token@") != 1:
        raise ValueError("dependency governance must mint exactly one independent author App token")
    if semantic.count("${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("dependency governance private key must have exactly one consumer")
    if semantic.count("${{ steps.promotion-author-app.outputs.token }}") != 1:
        raise ValueError("dependency governance author App token must have exactly one consumer")
    if semantic.count("security-events: write") != 1:
        raise ValueError("dependency post-merge CodeQL must own the only security-events write")
    if semantic.count("checks: write") != 1:
        raise ValueError(
            "dependency governance checks-write authority must remain isolated to govern"
        )

    mutation_guard = (
        "        if: steps.revision.outputs.current == 'true' && "
        "steps.post_merge_admission.outputs.mutation_ready == 'true'"
    )
    guarded_mutation_steps = (
        "Validate independent promotion author identity configuration",
        "Mint independent promotion author token",
        "Bind promotion author token to reviewed bot identity",
        "Reconcile exact-subject Python dependency promotion",
    )
    for step_name in guarded_mutation_steps:
        step = base._semantic_text(base._step_block(govern_job, step_name))
        if mutation_guard not in step:
            raise ValueError("dependency governance schedule-owned mutation admission drifted")
    dependabot_reconcile = base._semantic_text(
        base._step_block(govern_job, "Reconcile Dependabot action merge authority")
    )
    exact_dependabot_guard = mutation_guard + " && steps.python_promotion.outputs.merged != 'true'"
    if exact_dependabot_guard not in dependabot_reconcile:
        raise ValueError("dependency governance schedule-owned mutation admission drifted")

    mint = base._semantic_text(
        base._step_block(govern_job, "Mint independent promotion author token")
    )
    for forbidden_permission in (
        "permission-actions:",
        "permission-checks:",
        "permission-statuses:",
        "permission-workflows:",
        "permission-administration:",
    ):
        if forbidden_permission in mint:
            raise ValueError(
                f"dependency promotion author App has forbidden permission: {forbidden_permission}"
            )

    exact_revision = govern_job.index(
        "      - name: Verify exact current-main governance revision before mutation"
    )
    policy_validation = govern_job.index(
        "      - name: Validate trusted governance and recovery policy"
    )
    admission = govern_job.index(
        "      - name: Admit exact dependency post-merge validation before mutation"
    )
    recovery_step = govern_job.index("      - name: Attempt one bounded transient recovery")
    identity = govern_job.index(
        "      - name: Validate independent promotion author identity configuration"
    )
    mint_index = govern_job.index("      - name: Mint independent promotion author token")
    bind = govern_job.index("      - name: Bind promotion author token to reviewed bot identity")
    promotion = govern_job.index(
        "      - name: Reconcile exact-subject Python dependency promotion"
    )
    reconcile = govern_job.index("      - name: Reconcile Dependabot action merge authority")
    if not (
        exact_revision
        < policy_validation
        < admission
        < recovery_step
        < identity
        < mint_index
        < bind
        < promotion
        < reconcile
    ):
        raise ValueError(
            "dependency validation admission, recovery, promotion, and merge reconciliation order drifted"
        )

    observed = base._workflow_structure_sha1(text)
    if observed != EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "dependency-governance.yml non-action structure differs from reviewed dependency authority"
        )
    return {
        "triggers": ["workflow_run", "schedule"],
        "trusted_code_source": "exact-current-main",
        "recovery_authority": "one-rerun-no-branch-mutation-no-merge",
        "post_merge_validation_recovery": (
            "owner-schedule-canonical-reusable-ci+codeql-before-further-dependency-mutation"
        ),
        "post_merge_dispatch_authority": "none",
        "python_dependency_authority": "signed-dependabot-intent-to-deterministic-lock-promotion",
        "promotion_authority": (
            "independent-noncertifying-app:contents-write+pull-requests-write:new-subject-only"
        ),
        "reconciliation_concurrency": "single-global-mutex",
        "reconciliation_cadence": "five-minute-schedule-plus-reviewed-workflow-wakes",
        "trusted_revision": "exact-current-main-or-safe-noop-before-any-non-pr-mutation",
        "merge_authority": "single-provenance-qualified-dependabot-controller",
        "trusted_status_authority": "read-only-observation-of-centralized-app-gate",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_security_autoheal_pr_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "security-autoheal-pr.yml"
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  pull_request:",
            "    branches: [main]",
            "    types: [opened, synchronize, reopened, ready_for_review]",
            "    paths:",
            "      - '.github/security-autoheal.json'",
            "      - '.github/scripts/dependency_lock_compiler.py'",
            "      - '.github/scripts/security_alert_routing.py'",
            "      - '.github/scripts/security_autoheal.py'",
            "      - '.github/scripts/security_autoheal_selfcheck.py'",
            "      - '.github/scripts/trusted_qualification.py'",
            "      - '.github/scripts/trusted_status.py'",
            "      - '.github/workflows/security-autoheal-pr.yml'",
            "      - '.github/workflows/security-autoheal.yml'",
            "      - '.github/workflows/ci.yml'",
            "      - '.github/workflows/reusable-ci.yml'",
            "      - '.github/workflows/reusable-codeql.yml'",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "pull_request"
    }:
        raise ValueError(
            "security-autoheal-pr.yml must remain exact pull_request-only development evidence"
        )
    base._verify_top_level_read_only_permissions(text, name=name)
    env_block = base._semantic_text(base._top_level_block(text, "env")).strip("\n")
    expected_env = "\n".join(
        (
            "env:",
            '  PYTHONUNBUFFERED: "1"',
            '  PYTHONSAFEPATH: "1"',
            "  PYTHONPATH: .github/scripts",
            '  PIP_DISABLE_PIP_VERSION_CHECK: "1"',
            "  SECURITY_AUTOHEAL_CONFIG: .github/security-autoheal.json",
        )
    )
    if env_block != expected_env:
        raise ValueError("security-autoheal-pr.yml explicit safe import/config environment drifted")
    if base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError("security-autoheal-pr.yml must remain read-only")
    for forbidden in (
        "pull_request_target:",
        "workflow_run:",
        "status:",
        "schedule:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "environment:",
        "${{ secrets.",
        "${{ vars.",
        "${{ github.token }}",
        "GITHUB_TOKEN:",
        "continue-on-error: true",
        "ubuntu-latest",
        "actions/upload-artifact@",
        "actions/download-artifact@",
        "actions/create-github-app-token@",
        "--allow-merge",
        "--reconcile",
        "--plan-routes",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"security-autoheal-pr.yml contains forbidden authority token: {forbidden}"
            )
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    if (
        "  group: security-autoheal-pr-${{ github.event.pull_request.number }}" not in concurrency
        or "  cancel-in-progress: true" not in concurrency
    ):
        raise ValueError("security-autoheal-pr.yml stale-run cancellation contract drifted")
    self_test = base._semantic_text(base._job_block(text, "self-test"))
    required = (
        "    name: security-autoheal-self-test",
        "    permissions:\n      contents: read",
        "      - name: Checkout proposed security control plane without credentials",
        "          persist-credentials: false",
        "      - name: Compile security control plane",
        "      - name: Validate security auto-heal policy",
        "python .github/scripts/security_autoheal.py --validate-config --self-test",
        "      - name: Exercise security auto-heal self-check",
        "python .github/scripts/security_autoheal_selfcheck.py",
    )
    for fragment in required:
        if fragment not in self_test:
            raise ValueError(
                f"security-autoheal-pr.yml missing reviewed self-test invariant: {fragment}"
            )
    if semantic.count("actions/checkout@") != 1 or semantic.count("actions/setup-python@") != 1:
        raise ValueError(
            "security-autoheal-pr.yml must use exactly one reviewed checkout/setup pair"
        )
    if base._workflow_structure_sha1(text) != EXPECTED_SECURITY_AUTOHEAL_PR_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "security-autoheal-pr.yml non-action structure differs from reviewed secret-free definition"
        )
    return {
        "triggers": ["pull_request"],
        "authority": "development-evidence-only",
        "permissions": "contents:read",
        "secrets": "forbidden",  # pragma: allowlist secret
        "mutation": "forbidden",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_security_autoheal_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            "    workflows:",
            "      - CodeQL",
            "      - 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'",
            "    types: [completed]",
            "    branches:",
            "      - main",
            "  schedule:",
            "    - cron: '41 * * * *'",
            "  workflow_dispatch:",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on or base._top_level_keys(base._top_level_block(text, "on")) != {
        "workflow_run",
        "schedule",
        "workflow_dispatch",
    }:
        raise ValueError(
            "security-autoheal.yml must remain accepted-main workflow_run/schedule/workflow_dispatch only"
        )
    for forbidden_trigger in ("pull_request:", "pull_request_target:", "repository_dispatch:"):
        if forbidden_trigger in semantic:
            raise ValueError(
                "security-autoheal.yml privileged controller must never execute candidate PR workflow bytes"
            )
    base._verify_top_level_read_only_permissions(text, name="security-autoheal.yml")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    if (
        "  group: security-autoheal-reconcile" not in concurrency
        or "  cancel-in-progress: false" not in concurrency
    ):
        raise ValueError("security-autoheal.yml reconciliation concurrency contract drifted")
    if base._workflow_structure_sha1(text) != EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "security-autoheal.yml non-action structure differs from reviewed security authority"
        )
    route_wake_guard = (
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      github.event_name == 'workflow_dispatch' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.conclusion == 'success' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        github.event.workflow_run.name == "
        "'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'))"
    )
    reconcile_wake_guard = (
        "    if: >-\n"
        "      needs.route-plan.result == 'success' &&\n"
        "      needs.route-plan.outputs.current == 'true' &&\n"
        "      (github.event_name == 'schedule' ||\n"
        "      github.event_name == 'workflow_dispatch' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.conclusion == 'success' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        github.event.workflow_run.name == "
        "'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework')))"
    )
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {
        "route-plan",
        "reconcile",
        "approve",
        "merge",
    }:
        raise ValueError("security-autoheal.yml job authority set drifted")
    route_job = base._semantic_text(base._job_block(text, "route-plan"))
    reconcile_job = base._semantic_text(base._job_block(text, "reconcile"))
    approve_job = base._semantic_text(base._job_block(text, "approve"))
    merge_job = base._semantic_text(base._job_block(text, "merge"))
    expected_permissions = {
        "route-plan": {
            "actions": "read",
            "contents": "read",
            "pull-requests": "read",
            "security-events": "read",
        },
        "reconcile": {
            "actions": "write",
            "checks": "write",
            "contents": "write",
            "pull-requests": "write",
            "security-events": "write",
            "statuses": "read",
        },
        "approve": {
            "actions": "read",
            "checks": "read",
            "contents": "read",
            "pull-requests": "read",
            "security-events": "read",
            "statuses": "read",
        },
        "merge": {
            "actions": "read",
            "checks": "read",
            "contents": "write",
            "pull-requests": "write",
            "security-events": "read",
            "statuses": "read",
        },
    }
    for job_name, job_text in (
        ("route-plan", route_job),
        ("reconcile", reconcile_job),
        ("approve", approve_job),
        ("merge", merge_job),
    ):
        if _trusted_auto._job_permissions(job_text) != expected_permissions[job_name]:
            raise ValueError(
                f"security-autoheal.yml {job_name} permissions differ from reviewed authority"
            )
    if route_wake_guard not in route_job:
        raise ValueError(
            "security-autoheal.yml route-plan must accept only successful same-repository "
            "main or Trusted PR Auto workflow wakes"
        )
    if reconcile_wake_guard not in reconcile_job:
        raise ValueError(
            "security-autoheal.yml reconcile must require exact-current-main admission and "
            "only successful same-repository main or Trusted PR Auto workflow wakes"
        )

    repair_author_environment = (
        "    environment:\n      name: protected-remediation-author\n      deployment: false"
    )
    if reconcile_job.count(repair_author_environment) != 1:
        raise ValueError(
            "security-autoheal.yml repair publisher credentials must remain isolated to "
            "protected-remediation-author"
        )
    for phase_job in (route_job, approve_job, merge_job):
        if "name: protected-remediation-author" in phase_job:
            raise ValueError(
                "security-autoheal.yml repair publisher environment escaped reconciliation"
            )

    exact_checkout = "          ref: ${{ github.sha }}"
    moving_checkout = "          ref: ${{ github.event.repository.default_branch }}"
    for job in (route_job, reconcile_job, approve_job, merge_job):
        if job.count(exact_checkout) != 1 or moving_checkout in job:
            raise ValueError(
                "security-autoheal.yml must pin every authority phase to the exact "
                "workflow control revision"
            )

    if "      current: ${{ steps.revision.outputs.current }}" not in route_job:
        raise ValueError(
            "security-autoheal.yml route plan must export exact-current-main admission"
        )
    route_revision = base._semantic_text(
        base._step_block(
            route_job,
            "Verify exact current-main security controller before planning",
        )
    )
    for fragment in (
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        'live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'if [ "$live_main" = "$GITHUB_SHA" ]; then',
        'printf \'current=%s\\n\' "$current" >> "$GITHUB_OUTPUT"',
    ):
        if fragment not in route_revision:
            raise ValueError(
                "security-autoheal.yml route planning lacks exact-current-main revision proof"
            )
    for step_name in (
        "Validate trusted security route planner",
        "Plan exact-main deterministic security routes",
        "Persist exact-run route plan before mutation",
    ):
        step = base._semantic_text(base._step_block(route_job, step_name))
        if "        if: steps.revision.outputs.current == 'true'" not in step:
            raise ValueError(
                "security-autoheal.yml route planning and persistence must require "
                "exact-current-main admission"
            )
    if "      needs.route-plan.outputs.current == 'true' &&" not in reconcile_job:
        raise ValueError(
            "security-autoheal.yml mutation job must consume exact-current-main admission"
        )
    mutation_revision = base._semantic_text(
        base._step_block(
            reconcile_job,
            "Revalidate exact current-main security controller before mutation",
        )
    )
    for fragment in (
        'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        'live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
        'test "$live_main" = "$GITHUB_SHA"',
    ):
        if fragment not in mutation_revision:
            raise ValueError(
                "security-autoheal.yml mutation lacks immediate exact-current-main revalidation"
            )
    for phase_job, step_name, phase_label in (
        (
            approve_job,
            "Revalidate exact current-main owner-review controller",
            "owner approval",
        ),
        (
            merge_job,
            "Revalidate exact current-main security merge controller",
            "owner-approved merge",
        ),
    ):
        revision = base._semantic_text(base._step_block(phase_job, step_name))
        for fragment in (
            'test "$GITHUB_REF" = "refs/heads/main"',
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            'live_main="$(gh api "repos/${GITHUB_REPOSITORY}/branches/main" --jq .commit.sha)"',
            'test "$live_main" = "$GITHUB_SHA"',
        ):
            if fragment not in revision:
                raise ValueError(
                    f"security-autoheal.yml {phase_label} lacks immediate exact-current-main revalidation"
                )

    required = (
        "name: Security Auto-Heal",
        "  workflow_run:",
        "      - CodeQL",
        "      - 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'",
        "    branches:",
        "      - main",
        "  schedule:",
        "  workflow_dispatch:",
        "permissions:\n  contents: read",
        "  route-plan:",
        "    name: plan-codeql-autoheal-routes",
        "      actions: read",
        "      contents: read",
        "      pull-requests: read",
        "      security-events: read",
        "      current: ${{ steps.revision.outputs.current }}",
        "      artifact-id: ${{ steps.route-plan-artifact.outputs.artifact-id }}",
        "      artifact-digest: ${{ steps.route-plan-artifact.outputs.artifact-digest }}",
        "    name: reconcile-codeql-autoheal",
        "    needs: route-plan",
        "    environment:\n      name: protected-remediation-author\n      deployment: false",
        "      actions: write",
        "      checks: write",
        "      contents: write",
        "      pull-requests: write",
        "      security-events: write",
        "      statuses: read",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        "      - name: Plan exact-main deterministic security routes",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --plan-routes",
        '          --route-plan-output "$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json"',
        "      - name: Persist exact-run route plan before mutation",
        "        id: route-plan-artifact",
        "          name: security-autoheal-route-plan-${{ github.run_id }}-${{ github.run_attempt }}",
        "          path: ${{ runner.temp }}/security-autoheal-route-plan/route-plan.json",
        "          if-no-files-found: error",
        "          retention-days: 14",
        "      - name: Require accepted-main dependency validation before security mutation",
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
        "      - name: Validate independent security repair publisher identity configuration",
        "          AUTHOR_APP_CLIENT_ID: ${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}",
        "          AUTHOR_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "          AUTHOR_BOT_ID: ${{ vars.PROTECTED_REMEDIATION_BOT_ID }}",
        "      - name: Mint independent security repair publisher token",
        "        id: repair-author-app",
        "          private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
        "          permission-pull-requests: write",
        "      - name: Bind security repair publisher token to reviewed bot identity",
        "          OBSERVED_APP_SLUG: ${{ steps.repair-author-app.outputs.app-slug }}",
        "          EXPECTED_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "      - name: Restore exact-run route plan from prior read-only job",
        "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'",
        "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8",
        "          artifact-ids: ${{ needs.route-plan.outputs.artifact-id }}",
        "          path: ${{ runner.temp }}/security-autoheal-route-plan",
        "      - name: Reconcile exact-subject CodeQL remediations from persisted routes",
        "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'",
        "          SECURITY_AUTOHEAL_AUTHOR_TOKEN: ${{ steps.repair-author-app.outputs.token }}",
        "          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "          PROTECTED_REMEDIATION_BOT_ID: ${{ vars.PROTECTED_REMEDIATION_BOT_ID }}",
        "          --reconcile",
        '          --route-plan "$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json"',
        "          --route-artifact-id ${{ needs.route-plan.outputs.artifact-id }}",
        "          --route-artifact-name security-autoheal-route-plan-${{ github.run_id }}-${{ github.run_attempt }}",
        "          --route-artifact-digest sha256:${{ needs.route-plan.outputs.artifact-digest }}",
        "  approve:",
        "    name: Approve exact gated security repair as portyu9",
        "      name: portyu9-review-identity",
        "      lane: ${{ steps.owner-review.outputs.lane }}",
        "      pr_number: ${{ steps.owner-review.outputs.pr_number }}",
        "      - name: Require accepted-main dependency validation before security owner approval",
        "      - name: Publish exact security owner approval after Trusted PR Gate",
        "          PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
        "          --approve-owner-review",
        '          --github-output "$GITHUB_OUTPUT"',
        "  merge:",
        "    name: Merge exact owner-approved security repair",
        "      needs.approve.outputs.lane == 'security-autoheal' &&",
        "      - name: Require accepted-main dependency validation before security merge",
        "      - name: Merge exact owner-approved security repair",
        '          --merge-approved-pr "${{ needs.approve.outputs.pr_number }}"',
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(
                f"security-autoheal.yml missing reviewed authority invariant: {fragment}"
            )
    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "ubuntu-latest",
        "continue-on-error: true",
        "id-token: write",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "TRUSTED_STATUS_TOKEN",
        "statuses: write",
        "environment:\n      name: trusted-pr-gate",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"security-autoheal.yml contains forbidden authority token: {forbidden}"
            )
    barrier_step = base._semantic_text(
        base._step_block(
            reconcile_job,
            "Require accepted-main dependency validation before security mutation",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in barrier_step:
            raise ValueError(
                "security autoheal mutation lacks the read-only accepted-main dependency barrier"
            )
    mutation_step = base._semantic_text(
        base._step_block(
            reconcile_job,
            "Reconcile exact-subject CodeQL remediations from persisted routes",
        )
    )
    required_barrier_guard = "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'"
    if required_barrier_guard not in mutation_step:
        raise ValueError(
            "security autoheal mutation must require accepted-main dependency validation"
        )
    publisher_mint = base._semantic_text(
        base._step_block(reconcile_job, "Mint independent security repair publisher token")
    )
    for fragment in (
        "        id: repair-author-app",
        "          client-id: ${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}",
        "          private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
        "          owner: portyu9",
        "          repositories: ai-qa-automation",
        "          permission-pull-requests: write",
    ):
        if fragment not in publisher_mint:
            raise ValueError("security autoheal publisher App mint drifted from reviewed scope")
    for forbidden_permission in (
        "permission-actions:",
        "permission-checks:",
        "permission-contents:",
        "permission-security-events:",
        "permission-statuses:",
    ):
        if forbidden_permission in publisher_mint:
            raise ValueError(
                "security autoheal publisher App gained authority beyond pull-request publication"
            )
    if semantic.count("${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("security autoheal publisher App private key inventory drifted")
    if "${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}" not in reconcile_job:
        raise ValueError("security autoheal publisher App private key escaped reconciliation")
    for job in (route_job, approve_job, merge_job):
        if "${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}" in job:
            raise ValueError(
                "security autoheal publisher App private key leaked across authority phases"
            )
    if semantic.count("${{ steps.repair-author-app.outputs.token }}") != 1:
        raise ValueError("security autoheal publisher token must have exactly one consumer")
    if "${{ steps.repair-author-app.outputs.token }}" not in mutation_step:
        raise ValueError(
            "security autoheal publisher token must be isolated to repair reconciliation"
        )
    if "--allow-merge" in semantic:
        raise ValueError(
            "security autoheal authoring/reconcile phase must not retain merge authority"
        )
    if semantic.count("${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}") != 1:
        raise ValueError("security owner-review token must have exactly one workflow consumer")
    if "${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}" not in approve_job:
        raise ValueError("security owner-review token must be isolated to the approval job")
    for untrusted_job in (route_job, reconcile_job, merge_job):
        if "${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}" in untrusted_job:
            raise ValueError("security owner-review token leaked outside the approval job")
    if "environment:\n      name: portyu9-review-identity" not in approve_job:
        raise ValueError("security owner review must use the isolated review-identity environment")
    if "PORTYU9_BOT_REVIEW_TOKEN" in merge_job:
        raise ValueError("security merge authority must not receive the owner-review credential")
    approval_barrier = base._semantic_text(
        base._step_block(
            approve_job,
            "Require accepted-main dependency validation before security owner approval",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in approval_barrier:
            raise ValueError("security owner approval lacks accepted-main dependency revalidation")
    owner_publication = base._semantic_text(
        base._step_block(
            approve_job,
            "Publish exact security owner approval after Trusted PR Gate",
        )
    )
    if required_barrier_guard not in owner_publication:
        raise ValueError(
            "security owner credential use must require accepted-main dependency validation"
        )
    merge_barrier = base._semantic_text(
        base._step_block(
            merge_job,
            "Require accepted-main dependency validation before security merge",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in merge_barrier:
            raise ValueError(
                "security owner-approved merge lacks accepted-main dependency revalidation"
            )

    plan = semantic.index("      - name: Plan exact-main deterministic security routes")
    persist = semantic.index("      - name: Persist exact-run route plan before mutation")
    barrier = semantic.index(
        "      - name: Require accepted-main dependency validation before security mutation"
    )
    restore = semantic.index("      - name: Restore exact-run route plan from prior read-only job")
    reconcile = semantic.index(
        "      - name: Reconcile exact-subject CodeQL remediations from persisted routes"
    )
    if not plan < persist < barrier < restore < reconcile:
        raise ValueError(
            "security route planning, durable persistence, dependency barrier, artifact restoration, "
            "and mutation reconciliation are out of reviewed order"
        )
    return {
        "triggers": ["workflow_run", "schedule", "workflow_dispatch"],
        "trusted_code_source": "accepted-main-only",
        "trusted_revision": "exact-current-main-or-safe-noop-before-mutation",
        "candidate_workflow_execution": "forbidden",
        "repair_authority": (
            "read-only-plan-job-to-persisted-exact-run-route-before-write-authority"
        ),
        "merge_authority": "exact-owner-approved-security-subject-after-app-gate-reproof",
        "trusted_status_authority": "read-only-observation-of-centralized-app-gate",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_release_candidate_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "release-candidate.yml"
    semantic = base._semantic_text(text)
    if base._workflow_structure_sha1(text) != EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "release-candidate.yml non-action structure differs from the reviewed definition"
        )

    expected_on = "\n".join(
        (
            "on:",
            "  workflow_dispatch:",
            "    inputs:",
            "      release_tag:",
            "        description: Stable release tag matching pyproject.toml, for example v0.1.0",
            "        required: true",
            "        type: string",
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError("release-candidate.yml must be explicit workflow_dispatch only")
    if base._top_level_keys(base._top_level_block(text, "on")) != {"workflow_dispatch"}:
        raise ValueError("release-candidate.yml contains unreviewed trigger authority")

    base._verify_top_level_read_only_permissions(text, name=name)
    if base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError("release-candidate.yml native token must remain read-only")
    for forbidden in (
        "pull_request:",
        "pull_request_target:",
        "push:",
        "schedule:",
        "repository_dispatch:",
        "workflow_run:",
        "${{ secrets.",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "ANTHROPIC_API_KEY",
        "packages: write",
        "contents: write",
        "id-token: write",
        "gh release",
        "twine ",
        "pypi",
        "sigstore",
        "continue-on-error: true",
        "if: always()",
        "ubuntu-latest",
        "pip install --upgrade",
        " --editable",
        " -e .",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"release-candidate.yml contains forbidden authority token: {forbidden}"
            )
    if base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError("release-candidate.yml dependency caching is forbidden")

    env_block = base._semantic_text(base._top_level_block(text, "env")).strip("\n")
    expected_env = "\n".join(
        (
            "env:",
            '  PYTHONUNBUFFERED: "1"',
            '  PYTHONSAFEPATH: "1"',
            '  PIP_DISABLE_PIP_VERSION_CHECK: "1"',
            "  RELEASE_SUBJECT_SHA: ${{ github.sha }}",
        )
    )
    if env_block != expected_env:
        raise ValueError("release-candidate.yml release subject environment differs from review")

    required = (
        "    name: Deterministic Release Candidate Evidence",
        f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}",
        "ref: ${{ env.RELEASE_SUBJECT_SHA }}",
        "persist-credentials: false",
        'test "$GITHUB_REF" = "refs/heads/main"',
        'test "$(git rev-parse HEAD)" = "$RELEASE_SUBJECT_SHA"',
        'evidence_root="$RUNNER_TEMP/aiqa-release-candidate"',
        'mkdir -m 700 "$evidence_root"',
        'printf \'RELEASE_EVIDENCE_DIR=%s\\n\' "$evidence_root" >> "$GITHUB_ENV"',
        f"uses: actions/setup-python@{base.EXPECTED_ACTION_SHAS['actions/setup-python']}",
        'python-version: "3.11.16"',
        "python scripts/verify_release_candidate.py",
        '--expected-ref "$GITHUB_REF"',
        "python scripts/verify_build_authority.py",
        "python -m pip install --require-hashes -r requirements/build-py311.lock",
        'SOURCE_DATE_EPOCH: "315532800"',
        'archive --format=tar "$RELEASE_SUBJECT_SHA"',
        'cmp -s "$RELEASE_EVIDENCE_DIR/build-authority-archive-a.json" "$RELEASE_EVIDENCE_DIR/build-authority-archive-b.json"',
        '--wheel-a "${wheel_a[0]}"',
        '--wheel-b "${wheel_b[0]}"',
        '--output "$RELEASE_EVIDENCE_DIR/release-manifest.json"',
        "/usr/bin/sha256sum",
        '/usr/bin/git ls-remote "https://github.com/${GITHUB_REPOSITORY}.git" refs/heads/main',
        'test "$live_main" = "$RELEASE_SUBJECT_SHA"',
        '"$RELEASE_EVIDENCE_DIR/main-revalidation.json"',
        f"uses: actions/upload-artifact@{base.EXPECTED_ACTION_SHAS['actions/upload-artifact']}",
        "name: release-candidate-evidence",
        "${{ env.RELEASE_EVIDENCE_DIR }}/release-manifest.json",
        "${{ env.RELEASE_EVIDENCE_DIR }}/main-revalidation.json",
        "if-no-files-found: error",
        "retention-days: 30",
    )
    for snippet in required:
        if snippet not in semantic:
            raise ValueError(f"release-candidate.yml missing reviewed invariant: {snippet}")
    if (
        semantic.count(f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}")
        != 1
    ):
        raise ValueError("release-candidate.yml must have exactly one exact-subject checkout")
    if semantic.count("python scripts/verify_release_candidate.py") != 2:
        raise ValueError(
            "release-candidate.yml must verify identity before and after package build"
        )
    if semantic.count("python -m pip wheel --no-deps --no-build-isolation") != 2:
        raise ValueError("release-candidate.yml must build exactly two reviewed wheels")
    if semantic.count("python scripts/verify_build_authority.py --root") != 2:
        raise ValueError("release-candidate.yml must independently verify both archive roots")
    if semantic.count("/usr/bin/git ls-remote") != 1:
        raise ValueError(
            "release-candidate.yml must terminally revalidate current main exactly once"
        )

    return {
        "trigger": "workflow_dispatch",
        "source_ref": "refs/heads/main",
        "subject": "github.sha",
        "release_identity": "explicit-vMAJOR.MINOR.PATCH/static-project-version",
        "builds": 2,
        "package_reproducibility": "byte-identical-wheel-required",
        "build_authority": "hash-locked-and-archive-revalidated",
        "evidence": "runner-owned-canonical-manifest-plus-sha256-checksums",
        "terminal_main_revalidation": True,
        "failed_run_artifact_publication": "forbidden",
        "permissions": "contents:read",
        "publishing_authority": "none",
        "signature_claim": "none",
        "merge_authority": "none",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_protected_remediation_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if base._workflow_structure_sha1(text) != EXPECTED_PROTECTED_REMEDIATION_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "protected-security-remediation.yml structure differs from reviewed authority"
        )
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            '    workflows: ["Security Auto-Heal"]',
            "    types: [completed]",
            "  schedule:",
            '    - cron: "*/5 * * * *"',
        )
    )
    if base._semantic_text(base._top_level_block(text, "on")).strip("\n") != expected_on:
        raise ValueError(
            "protected remediation workflow must expose only reviewed trusted-main wakes"
        )
    if base._top_level_keys(base._top_level_block(text, "on")) != {"workflow_run", "schedule"}:
        raise ValueError("protected remediation workflow exposes an unreviewed trigger")
    base._verify_top_level_read_only_permissions(text, name="protected-security-remediation.yml")
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {
        "reconcile",
        "approve",
        "merge",
    }:
        raise ValueError("protected remediation workflow job authority set drifted")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    for fragment in (
        "  group: protected-security-remediation-reconcile",
        "  cancel-in-progress: false",
    ):
        if fragment not in concurrency:
            raise ValueError("protected remediation concurrency contract drifted")

    for forbidden in (
        "pull_request:",
        "pull_request_target:",
        "workflow_dispatch:",
        "repository_dispatch:",
        "continue-on-error: true",
        "ubuntu-latest",
        "skip-token-revoke:",
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"protected remediation workflow contains forbidden authority token: {forbidden}"
            )
    if base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError("protected remediation workflow dependency caching is forbidden")

    job = base._semantic_text(base._job_block(text, "reconcile"))
    approve_job = base._semantic_text(base._job_block(text, "approve"))
    merge_job = base._semantic_text(base._job_block(text, "merge"))
    expected_permissions = {
        "reconcile": {
            "actions": "read",
            "checks": "read",
            "contents": "read",
            "issues": "write",
            "pull-requests": "write",
            "security-events": "read",
            "statuses": "read",
        },
        "approve": {
            "actions": "read",
            "checks": "read",
            "contents": "read",
            "pull-requests": "read",
            "security-events": "read",
            "statuses": "read",
        },
        "merge": {
            "actions": "read",
            "checks": "read",
            "contents": "read",
            "pull-requests": "read",
            "security-events": "read",
            "statuses": "read",
        },
    }
    for job_name, job_text in (
        ("reconcile", job),
        ("approve", approve_job),
        ("merge", merge_job),
    ):
        if _trusted_auto._job_permissions(job_text) != expected_permissions[job_name]:
            raise ValueError(
                f"protected remediation {job_name} permissions differ from reviewed authority"
            )
    required_job = (
        "    name: Independent Protected Remediation Reconcile",
        "    if: >-\n      github.event_name == 'schedule' ||\n      (github.event_name == 'workflow_run' &&\n       github.event.workflow_run.conclusion == 'success' &&\n       github.event.workflow_run.head_repository.full_name == github.repository &&\n       github.event.workflow_run.head_sha == github.sha)",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    env:\n      PROTECTED_REMEDIATION_CONTROL_SHA: ${{ github.sha }}",
        "    outputs:\n      author_bot_login: ${{ steps.author-identity.outputs.login }}\n      author_bot_id: ${{ steps.author-identity.outputs.id }}",
        "    environment:\n      name: protected-remediation-author\n      deployment: false",
        "      - name: Checkout trusted default-branch control plane",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        '        run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        '          python-version: "3.11.16"',
        "      - name: Verify current trusted protected-remediation control revision",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python .github/scripts/protected_security_remediation.py\n          --validate-control-revision",
        "      - name: Require accepted-main dependency validation before protected mutation",
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
        "      - name: Validate independent author identity configuration",
        "        id: author-identity",
        '            "github-actions[bot]"|"dependabot[bot]"|"trusted-pr-gate[bot]") exit 1 ;;',
        '          printf \'login=%s\\n\' "$AUTHOR_BOT_LOGIN" >> "$GITHUB_OUTPUT"',
        '          printf \'id=%s\\n\' "$AUTHOR_BOT_ID" >> "$GITHUB_OUTPUT"',
        "      - name: Mint dedicated protected-remediation author token",
        "      - name: Bind minted App to reviewed bot identity",
        '          test "${OBSERVED_APP_SLUG}[bot]" = "$EXPECTED_BOT_LOGIN"',
        "      - name: Reconcile protected security remediation",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          PROTECTED_REMEDIATION_APP_TOKEN: ${{ steps.author-app.outputs.token }}",
        "          python .github/scripts/protected_security_remediation.py --reconcile",
    )
    for fragment in required_job:
        if fragment not in job:
            raise ValueError(
                f"protected remediation reconcile is missing reviewed fragment: {fragment}"
            )

    barrier = base._semantic_text(
        base._step_block(
            job,
            "Require accepted-main dependency validation before protected mutation",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in barrier:
            raise ValueError(
                "protected remediation lacks the read-only accepted-main dependency barrier"
            )
    required_barrier_guard = "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'"
    for step_name in (
        "Validate independent author identity configuration",
        "Mint dedicated protected-remediation author token",
        "Bind minted App to reviewed bot identity",
        "Reconcile protected security remediation",
    ):
        guarded_step = base._semantic_text(base._step_block(job, step_name))
        if required_barrier_guard not in guarded_step:
            raise ValueError(
                "protected remediation credential and mutation steps must require "
                "accepted-main dependency validation"
            )

    mint = base._semantic_text(
        base._step_block(job, "Mint dedicated protected-remediation author token")
    )
    required_mint = (
        "        id: author-app",
        f"        uses: actions/create-github-app-token@{EXPECTED_PROTECTED_AUTHOR_ACTION_SHA} # v3.2.0",
        "          client-id: ${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}",
        "          private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
        "          owner: portyu9",
        "          repositories: ai-qa-automation",
        "          permission-contents: write",
        "          permission-pull-requests: write",
    )
    for fragment in required_mint:
        if fragment not in mint:
            raise ValueError(
                f"protected remediation App mint is missing reviewed fragment: {fragment}"
            )
    for forbidden_permission in (
        "permission-actions:",
        "permission-checks:",
        "permission-statuses:",
        "permission-workflows:",
        "permission-administration:",
    ):
        if forbidden_permission in mint:
            raise ValueError(
                f"protected remediation author App has forbidden permission: {forbidden_permission}"
            )
    if semantic.count("actions/create-github-app-token@") != 2:
        raise ValueError(
            "protected remediation must mint exactly one author token and one separate merge token"
        )
    if semantic.count("${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}") != 2:
        raise ValueError(
            "protected remediation App private key must be isolated to author and merge mints"
        )
    if semantic.count("${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}") != 1:
        raise ValueError("protected owner-review token must have exactly one workflow consumer")
    if "${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}" not in approve_job:
        raise ValueError("protected owner-review token must be isolated to the approval job")
    if "${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}" in approve_job:
        raise ValueError("protected owner-review job must not receive the remediation App key")
    if (
        "${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}" in job
        or "${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}" in merge_job
    ):
        raise ValueError("protected owner credential leaked into authoring or merge authority")
    if "environment:\n      name: portyu9-review-identity" not in approve_job:
        raise ValueError("protected owner review must use the isolated review-identity environment")
    if "environment:\n      name: protected-remediation-author" not in job:
        raise ValueError("protected authoring job lost its dedicated environment")
    if "environment:\n      name: protected-remediation-author" not in merge_job:
        raise ValueError("protected merge job lost its dedicated App environment")
    if "--allow-merge" in semantic:
        raise ValueError("protected authoring/reconcile job must not retain direct merge authority")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}") != 4:
        raise ValueError("protected remediation App client id consumer count drifted")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}") != 6:
        raise ValueError("protected remediation bot login consumer count drifted")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_BOT_ID }}") != 4:
        raise ValueError("protected remediation bot id consumer count drifted")
    if semantic.count("${{ steps.author-app.outputs.token }}") != 1:
        raise ValueError("protected authoring App token must have exactly one execution consumer")
    if semantic.count("${{ steps.author-app.outputs.app-slug }}") != 1:
        raise ValueError("protected authoring App slug must be checked exactly once")
    if semantic.count("${{ steps.merge-author-app.outputs.token }}") != 1:
        raise ValueError("protected merge App token must have exactly one execution consumer")
    if semantic.count("${{ steps.merge-author-app.outputs.app-slug }}") != 1:
        raise ValueError("protected merge App slug must be checked exactly once")
    if semantic.count("persist-credentials: false") != 3:
        raise ValueError("every protected authority phase must disable persisted credentials")
    if semantic.count("ref: ${{ github.sha }}") != 3:
        raise ValueError("every protected authority phase must checkout exact accepted main")

    approve_required = (
        "    name: Approve exact gated protected repair as portyu9",
        "    needs: reconcile",
        "      name: portyu9-review-identity",
        "      lane: ${{ steps.owner-review.outputs.lane }}",
        "      pr_number: ${{ steps.owner-review.outputs.pr_number }}",
        "      - name: Require accepted-main dependency validation before protected owner approval",
        "      - name: Publish exact protected security owner approval after Trusted PR Gate",
        "          PORTYU9_BOT_REVIEW_TOKEN: ${{ secrets.PORTYU9_BOT_REVIEW_TOKEN }}",
        "          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ needs.reconcile.outputs.author_bot_login }}",
        "          PROTECTED_REMEDIATION_BOT_ID: ${{ needs.reconcile.outputs.author_bot_id }}",
        "          --approve-owner-review",
        '          --github-output "$GITHUB_OUTPUT"',
    )
    for fragment in approve_required:
        if fragment not in approve_job:
            raise ValueError(
                f"protected remediation owner-review phase is missing reviewed fragment: {fragment}"
            )
    approval_barrier = base._semantic_text(
        base._step_block(
            approve_job,
            "Require accepted-main dependency validation before protected owner approval",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in approval_barrier:
            raise ValueError("protected owner approval lacks accepted-main dependency revalidation")
    owner_publication = base._semantic_text(
        base._step_block(
            approve_job,
            "Publish exact protected security owner approval after Trusted PR Gate",
        )
    )
    if (
        "        if: steps.post_merge_barrier.outputs.mutation_ready == 'true'"
        not in owner_publication
    ):
        raise ValueError(
            "protected owner credential use must require accepted-main dependency validation"
        )
    for fragment in (
        "          PROTECTED_REMEDIATION_BOT_LOGIN: ${{ needs.reconcile.outputs.author_bot_login }}",
        "          PROTECTED_REMEDIATION_BOT_ID: ${{ needs.reconcile.outputs.author_bot_id }}",
    ):
        if fragment not in owner_publication:
            raise ValueError("protected owner approval must consume reconciler identity outputs")
    for forbidden_scoped_var in (
        "${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}",
        "${{ vars.PROTECTED_REMEDIATION_BOT_ID }}",
    ):
        if forbidden_scoped_var in approve_job:
            raise ValueError("protected owner approval must consume reconciler identity outputs")
    merge_required = (
        "    name: Merge exact owner-approved protected repair",
        "    needs: [reconcile, approve]",
        "      needs.approve.outputs.lane == 'protected-security-remediation' &&",
        "      - name: Require accepted-main dependency validation before protected merge",
        "      - name: Mint dedicated protected-remediation merge token",
        "        id: merge-author-app",
        f"        uses: actions/create-github-app-token@{EXPECTED_PROTECTED_AUTHOR_ACTION_SHA} # v3.2.0",
        "      - name: Merge exact owner-approved protected repair",
        '          --merge-approved-pr "${{ needs.approve.outputs.pr_number }}"',
    )
    for fragment in merge_required:
        if fragment not in merge_job:
            raise ValueError(
                f"protected remediation merge phase is missing reviewed fragment: {fragment}"
            )
    merge_barrier = base._semantic_text(
        base._step_block(
            merge_job,
            "Require accepted-main dependency validation before protected merge",
        )
    )
    for fragment in (
        "        id: post_merge_barrier",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          --check-post-merge",
        '          --github-output "$GITHUB_OUTPUT"',
    ):
        if fragment not in merge_barrier:
            raise ValueError(
                "protected owner-approved merge lacks accepted-main dependency revalidation"
            )
    merge_mint = base._semantic_text(
        base._step_block(merge_job, "Mint dedicated protected-remediation merge token")
    )
    for fragment in (
        "        id: merge-author-app",
        f"        uses: actions/create-github-app-token@{EXPECTED_PROTECTED_AUTHOR_ACTION_SHA} # v3.2.0",
        "          client-id: ${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}",
        "          private-key: ${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}",
        "          owner: portyu9",
        "          repositories: ai-qa-automation",
        "          permission-contents: write",
        "          permission-pull-requests: write",
    ):
        if fragment not in merge_mint:
            raise ValueError(f"protected merge App mint is missing reviewed fragment: {fragment}")

    control_position = job.index(
        "      - name: Verify current trusted protected-remediation control revision"
    )
    barrier_position = job.index(
        "      - name: Require accepted-main dependency validation before protected mutation"
    )
    mint_position = job.index("      - name: Mint dedicated protected-remediation author token")
    reconcile_position = job.index("      - name: Reconcile protected security remediation")
    if not control_position < barrier_position < mint_position < reconcile_position:
        raise ValueError(
            "protected remediation control/barrier/mint/reconcile steps are out of reviewed order"
        )
    return {
        "trigger": "workflow_run:Security Auto-Heal:completed+schedule:5m",
        "trusted_definition": "default-branch-exact-main-workflow-run-or-schedule",
        "native_token": "read+issues-write-terminal-certificate",
        "terminal_certificate_writer": "github-actions[bot]",
        "author_token": "distinct-app:contents-write+pull-requests-write",
        "owner_review": "isolated-portyu9-exact-head-approval-before-merge",
        "status_authority": "none",
        "candidate_workflow_execution": "forbidden",
        "mutation": "exact-route+one-file+branch-pr-only",
    }


def _verify_ruleset_reconciler_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if base._workflow_structure_sha1(text) != EXPECTED_RULESET_RECONCILER_WORKFLOW_BLOB_SHA:
        raise ValueError("ruleset-reconciler.yml structure differs from reviewed authority")

    expected_on = "\n".join(
        (
            "on:",
            "  push:",
            "    branches: [main]",
            "  schedule:",
            '    - cron: "23 */6 * * *"',
            "  workflow_dispatch:",
        )
    )
    if base._semantic_text(base._top_level_block(text, "on")).strip("\n") != expected_on:
        raise ValueError("ruleset reconciler trigger set drifted")
    if base._permissions(base._top_level_block(text, "permissions")) != {"contents": "read"}:
        raise ValueError("ruleset reconciler top-level token must remain contents-read-only")

    plan = base._semantic_text(base._job_block(text, "plan"))
    reconcile = base._semantic_text(base._job_block(text, "reconcile"))
    if "${{ secrets." in plan or "environment:" in plan:
        raise ValueError("ruleset plan must remain secret-free and environment-free")
    if _trusted_auto._job_permissions(reconcile) != {"contents": "read"}:
        raise ValueError("ruleset admin job native token must remain contents-read-only")
    if plan.count("classify-observable --live live-plan.json") != 1:
        raise ValueError("ruleset read-only plan must use exactly one observable classification")
    if "classify --live live-plan.json" in plan:
        raise ValueError(
            "ruleset read-only plan must not require administration-only observability"
        )
    exact_admin_reproof = (
        'before_state="$(python3 scripts/ruleset_transition_contract.py classify --live '
        '"$RUNNER_TEMP/ruleset-before.json")"'
    )
    if exact_admin_reproof not in reconcile or "classify-observable" in reconcile:
        raise ValueError("ruleset admin job must re-prove exact live state before mutation")

    required = (
        "  group: ruleset-reconciler-global",
        "  cancel-in-progress: false",
        "    environment: ruleset-admin-identity",
        "          ADMIN_APP_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_APP_ID }}",
        "          ADMIN_INSTALLATION_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_INSTALLATION_ID }}",
        "          ADMIN_PRIVATE_KEY: ${{ secrets.PORTYU9_RULESET_ADMIN_PRIVATE_KEY }}",
        "          TRANSITION_DIGEST: sha256:4d8b2c205c444477702214c936c851a45c924ee88e2cff5e67e3d70bafa28716",
        "          python3 scripts/ruleset_transition_contract.py validate --transition-digest",
        '          live_state="$(python3 scripts/ruleset_transition_contract.py classify-observable --live live-plan.json)"',
        "          python3 scripts/ruleset_transition_contract.py emit-put",
        '          before_state="$(python3 scripts/ruleset_transition_contract.py classify --live "$RUNNER_TEMP/ruleset-before.json")"',
        '            (.permissions.administration == "write") and',
        '            ((.permissions | keys - ["administration", "metadata"]) | length == 0) and',
        "            -f 'repositories[]=ai-qa-automation' \\",
        "            -f 'permissions[administration]=write' > \"$token_file\"",
        "            (.repositories[0].id == 1341984495) and",
        '            (.repositories[0].full_name == "portyu9/ai-qa-automation") and',
        '          GH_TOKEN="$admin_token" gh api --method PUT \\',
        "            repos/portyu9/ai-qa-automation/rulesets/21201916 \\",
        "          python3 scripts/ruleset_transition_contract.py require-successor",
        '          receipt_sha256="$(python3 scripts/ruleset_transition_contract.py receipt \\',
        "      - name: Preserve exact non-secret reconciliation receipt",
    )
    for secret in (
        "PORTYU9_RULESET_ADMIN_APP_ID",
        "PORTYU9_RULESET_ADMIN_INSTALLATION_ID",
        "PORTYU9_RULESET_ADMIN_PRIVATE_KEY",
    ):
        secret_reference = "${{ secrets." + secret + " }}"
        if semantic.count(secret_reference) != 1:
            raise ValueError(f"ruleset admin secret inventory drifted: {secret}")

    for fragment in required:
        if fragment not in semantic:
            raise ValueError(
                f"ruleset reconciler is missing reviewed authority fragment: {fragment}"
            )

    if semantic.count("gh api --method PUT") != 1:
        raise ValueError("ruleset reconciler must contain exactly one administration PUT")
    if semantic.count("permissions[administration]=write") != 1:
        raise ValueError("ruleset reconciler must request Administration write exactly once")
    if reconcile.count("Authorization: Bearer ${app_jwt}") != 2:
        raise ValueError(
            "ruleset App JWT requests must use explicit Bearer authorization exactly twice"
        )
    if 'GH_TOKEN="$app_jwt" gh api "app/installations/' in reconcile:
        raise ValueError("ruleset App JWT requests must not rely on gh token scheme inference")
    if semantic.count("actions/checkout@") != 2:
        raise ValueError("ruleset reconciler must have exactly two trusted-main checkouts")
    if semantic.count("persist-credentials: false") != 2:
        raise ValueError("ruleset reconciler checkouts must disable persisted credentials")
    if semantic.count("actions/upload-artifact@") != 1:
        raise ValueError("ruleset reconciler must preserve exactly one receipt artifact")

    for forbidden in (
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
        "ACTIONS_ID_TOKEN_REQUEST_",
    ):
        if forbidden in semantic:
            raise ValueError(f"ruleset reconciler contains forbidden authority: {forbidden}")

    return {
        "trigger": "accepted-main-push+6h-schedule+manual-recovery",
        "native_token": "contents-read-only",
        "admin_identity": "ruleset-admin-identity",
        "admin_token": "dedicated-app:administration-write+metadata-only",
        "transition": "exact-predecessor-to-exact-successor-one-put",
        "recovery": "non-replaying-readback",
        "receipt": "non-secret-artifact",
    }


def _verify_ruleset_drift_witness(root: Path) -> dict[str, Any]:
    path = root / ".github" / "rulesets" / "ruleset-drift-witness-v1.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("ruleset drift witness must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_RULESET_DRIFT_WITNESS_BLOB_SHA:
        raise ValueError("ruleset drift witness differs from the reviewed full-state certification")
    payload = json.loads(text)
    expected = {
        "schemaVersion": 1,
        "repository": "portyu9/ai-qa-automation",
        "repositoryId": 1341984495,
        "rulesetId": 21201916,
        "rulesetName": "Protect Main",
        "createdAt": "2026-08-22T16:08:51.163+00:00",
        "updatedAt": "2026-10-02T00:02:13.137+00:00",
        "successorDigest": "sha256:bd50c4ad608a2c23d288a7ebb32fe77a5a270585adbe0c92133c808318a71929",
        "transitionDigest": "sha256:4d8b2c205c444477702214c936c851a45c924ee88e2cff5e67e3d70bafa28716",
        "bypassActors": [],
        "requiredStatus": {"context": "Trusted PR Gate", "integrationId": 4766700},
        "certification": {
            "reconcilerRunId": 36943897969,
            "reconcilerArtifactId": 11201033580,
            "reconcilerArtifactDigest": "sha256:66e50814b5201d1986b1fa3bbf8a8014ab4081730c76862a22937b027c09aaf0",
            "reconcilerReceiptDigest": "sha256:0fadac6bd1a1407feac960685efc7473e7f81d09fd0f32a06e9460a78e063e11",
        },
    }
    if payload != expected:
        raise ValueError("ruleset drift witness semantic fields drifted")
    return {
        "authority": "reviewed-full-state-certification",
        "updated_at": expected["updatedAt"],
        "bypass_actors": "certified-empty",
        "reconciler_run_id": expected["certification"]["reconcilerRunId"],
    }


def _verify_ruleset_drift_sentinel_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if base._workflow_structure_sha1(text) != EXPECTED_RULESET_DRIFT_SENTINEL_WORKFLOW_BLOB_SHA:
        raise ValueError("ruleset-drift-sentinel.yml structure differs from reviewed definition")

    expected_on = "\n".join(
        (
            "on:",
            "  schedule:",
            '    - cron: "47 */6 * * *"',
            "  workflow_dispatch:",
        )
    )
    if base._semantic_text(base._top_level_block(text, "on")).strip("\n") != expected_on:
        raise ValueError("ruleset drift sentinel trigger set drifted")
    if base._permissions(base._top_level_block(text, "permissions")) != {"contents": "read"}:
        raise ValueError("ruleset drift sentinel native token must remain contents-read-only")
    job = base._semantic_text(base._job_block(text, "validate"))
    if _trusted_auto._job_permissions(job) != {"contents": "read"}:
        raise ValueError("ruleset drift sentinel job token must remain contents-read-only")
    if "${{ secrets." in semantic:
        raise ValueError("ruleset drift sentinel must remain secret-free")

    required = (
        "  group: ruleset-drift-sentinel",
        "  cancel-in-progress: false",
        "          TRANSITION_DIGEST: sha256:4d8b2c205c444477702214c936c851a45c924ee88e2cff5e67e3d70bafa28716",
        "          python3 scripts/ruleset_transition_contract.py validate --transition-digest",
        '          GH_TOKEN="$GITHUB_TOKEN" gh api repos/portyu9/ai-qa-automation/rulesets/21201916',
        "          python3 scripts/ruleset_transition_contract.py require-witnessed-successor \\",
        "            --witness .github/rulesets/ruleset-drift-witness-v1.json",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(f"ruleset drift sentinel is missing reviewed fragment: {fragment}")

    for forbidden in (
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
        "gh api --method",
        "gh api graphql",
        "aws-actions/",
        "ACTIONS_ID_TOKEN_REQUEST_",
        "curl ",
        "wget ",
    ):
        if forbidden in semantic:
            raise ValueError(f"ruleset drift sentinel contains forbidden authority: {forbidden}")

    mutation_api_re = re.compile(
        r"\bgh\s+api\b[^\n]*(?:(?:--method(?:=|\s+)|-X\s+)(?:POST|PUT|PATCH|DELETE)\b|graphql\b)",
        re.IGNORECASE,
    )
    if mutation_api_re.search(semantic):
        raise ValueError("ruleset drift sentinel contains forbidden repository mutation API form")
    if semantic.count("gh api") != 3:
        raise ValueError("ruleset drift sentinel GitHub API call inventory drifted")
    if semantic.count("actions/checkout@") != 1:
        raise ValueError("ruleset drift sentinel must have exactly one trusted-main checkout")
    if semantic.count("persist-credentials: false") != 1:
        raise ValueError("ruleset drift sentinel checkout must disable persisted credentials")
    if (
        semantic.count(
            'GH_TOKEN="$GITHUB_TOKEN" gh api repos/portyu9/ai-qa-automation/rulesets/21201916'
        )
        != 1
    ):
        raise ValueError(
            "ruleset drift sentinel must perform exactly one native read-only ruleset GET"
        )
    if semantic.count("gh api repos/portyu9/ai-qa-automation/git/ref/heads/main") != 2:
        raise ValueError("ruleset drift sentinel must re-prove live main around the ruleset read")

    return {
        "trigger": "6h-schedule+manual-read-only",
        "native_token": "contents-read-only",
        "admin_identity": "none",
        "credential_authority": "forbidden",
        "mutation": "forbidden",
        "witness": "exact-reviewed-full-state-revision",
        "desired_state": "Trusted PR Gate integration 4766700 exact successor",
    }


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    base = _trusted_auto._base
    _verify_frozen_trusted_auto_extension()
    _trusted_auto._verify_frozen_base()
    _trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
    base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES

    snapshots = base._read_workflow_set(root / ".github" / "workflows")
    workflows = {name: snapshot.text for name, snapshot in snapshots.items()}
    actions = base._verify_action_revisions(workflows)
    base.EXPECTED_ACTION_SHAS.update(actions)
    ordinary = _verify_ordinary_ci_workflow(workflows["ci.yml"])
    codeql = _verify_codeql_workflow(workflows["codeql.yml"])
    dependency_governance_pr = _verify_dependency_governance_pr_workflow(
        workflows["dependency-governance-pr.yml"]
    )
    dependency_governance = _verify_dependency_governance_workflow(
        workflows["dependency-governance.yml"]
    )
    dependency_trusted_merge = _verify_dependency_trusted_merge_workflow(
        workflows["dependency-trusted-merge.yml"]
    )
    manual = base._verify_manual_workflow(workflows["manual-validation.yml"])
    post_merge_ci = _verify_post_merge_ci_workflow(workflows["post-merge-ci.yml"])
    reusable_ci = _verify_reusable_ci_workflow(workflows["reusable-ci.yml"])
    reusable_codeql = _verify_reusable_codeql_workflow(workflows["reusable-codeql.yml"])
    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])
    security_autoheal_pr = _verify_security_autoheal_pr_workflow(
        workflows["security-autoheal-pr.yml"]
    )
    security_autoheal = _verify_security_autoheal_workflow(workflows["security-autoheal.yml"])
    protected_remediation = _verify_protected_remediation_workflow(
        workflows["protected-security-remediation.yml"]
    )
    ruleset_drift_sentinel = _verify_ruleset_drift_sentinel_workflow(
        workflows["ruleset-drift-sentinel.yml"]
    )
    ruleset_reconciler = _verify_ruleset_reconciler_workflow(workflows["ruleset-reconciler.yml"])
    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(workflows["trusted-pr-auto.yml"])
    _verify_ruleset_drift_witness(root)
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository workflow definitions satisfy deterministic CI authority invariants",
        "workflows": {
            "automatic": ordinary,
            "codeql": codeql,
            "dependency_governance_pr": dependency_governance_pr,
            "dependency_governance": dependency_governance,
            "dependency_trusted_merge": dependency_trusted_merge,
            "manual": manual,
            "post_merge_ci": post_merge_ci,
            "reusable_ci": reusable_ci,
            "reusable_codeql": reusable_codeql,
            "protected_remediation": protected_remediation,
            "release_candidate": release_candidate,
            "ruleset_drift_sentinel": ruleset_drift_sentinel,
            "ruleset_reconciler": ruleset_reconciler,
            "security_autoheal_pr": security_autoheal_pr,
            "security_autoheal": security_autoheal,
            "trusted_auto": trusted_auto,
        },
        "workflow_sizes": {
            name: snapshot.size_bytes for name, snapshot in sorted(snapshots.items())
        },
        "actions": actions,
        "limitations": [
            (
                "Ordinary pull_request execution is automatic read-only development evidence, not "
                "protected merge authority."
            ),
            (
                "CodeQL has narrowly scoped security-events write authority and no contents, "
                "status, pull-request, or merge authority; its v4 action revision may advance only "
                "within the reviewed semantic workflow contract."
            ),
            (
                "Dependency recovery may request at most one rerun for code-owned transient "
                "infrastructure failures; it cannot mutate branches, publish trusted status, or merge."
            ),
            (
                "Dependency governance consumes the App-owned Trusted PR Gate only after exact "
                "bot/provenance/check proofs; it does not hold App status-write credentials itself. "
                "A separate one-way accepted-main dependency merger wakes only from completed Trusted "
                "PR Auto Gate runs and rebinds that exact run to zero or one live dependency subject "
                "before invoking the existing exact-target merge policy."
            ),
            (
                "Dependency and Security Auto-Heal PR self-tests run in separate read-only, secret-free workflows. "
                "Their privileged controllers have no pull_request trigger, so candidate workflow bytes cannot "
                "request repository mutation authority; accepted-main controllers retain the reviewed bounded "
                "reconciliation capabilities and independently revalidate exact subjects before mutation."
            ),
            (
                "The release-candidate workflow is manual, read-only, and non-publishing; its "
                "manifest/checksums are integrity evidence, not publisher identity, signing, "
                "deployment approval, or protected merge authority."
            ),
            (
                "Automatic Trusted PR Gate admission refuses protected changes for owner-routine PRs. "
                "Owner-protected maintenance is separately admissible only from a durable exact owner authorization "
                "that trusted main independently discovers and revalidates. Any already-reviewed successful workflow-run "
                "wake may supply neutral reconciliation liveness, and schedule remains an independent fallback. "
                "The legacy issue-comment maintenance wake is retired because GitHub instantiated zero-job startup_failure "
                "runs even for unrelated issue comments; such runs are never authority or evidence. No wake selects the "
                "protected subject or contributes authorization. Trusted reconciliation is "
                "serialized per accepted-main SHA with cancel-in-progress disabled, so redundant wakes cannot run "
                "competing authority graphs for the same control revision. The controller independently "
                "reconciles exact owner/comment identity plus exact PR/head/base/merge inputs and a non-empty protected "
                "transition set; governed bot lanes retain their independent lane-specific provenance proofs."
            ),
            (
                "Recognized Dependabot Actions, deterministic dependency-promotion, CodeQL auto-heal, and "
                "independently App-authored protected-remediation subjects remain autonomous. Explicit "
                "owner-protected maintenance runs the same exact prospective-merge validation graph, including "
                "dedicated candidate CodeQL, before the terminal reporter can mint the dedicated App token. "
                "Candidate validation remains secret-free; the external service is compatibility/fallback, "
                "not a normal dependency of bot or GitHub-native owner-maintenance operation."
            ),
            (
                "The protected-owner authorization comment is consumed only inside accepted-main trusted "
                "reconciliation after a reviewed successful workflow-run wake or schedule fallback, plus exact live "
                "controller revalidation. Wake identity and outcome are liveness only and grant no authorization. A PR that "
                "introduces or repairs this policy remains a separately documented bootstrap boundary until the "
                "accepted-main revision proves the dedicated-App path."
            ),
            (
                "The trusted-pr-gate Environment/App credential remains required by the routine "
                "automatic reporter and must not be retired while that live path depends on it."
            ),
            (
                "Repository code cannot attest external break-glass deployment state, Environment "
                "protection, App installation, ruleset binding, or hosted infrastructure state; "
                "those require live external evidence."
            ),
            (
                "Trusted PR Gate is published on the PR head with an exact PR/base/head/merge-bound "
                "target and terminal live revalidation; protected-branch enforcement must still remain "
                "strict/up-to-date as an independent defense in depth."
            ),
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    verify_ci_contract(root)
    print(
        json.dumps(
            {"schema_version": 1, "result": "PASS", "verifier": "ci-contract"}, sort_keys=True
        )
    )


if __name__ == "__main__":
    main()
