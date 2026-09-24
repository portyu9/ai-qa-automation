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
    "dependency-governance.yml",
    "manual-validation.yml",
    "protected-security-remediation.yml",
    "release-candidate.yml",
    "security-autoheal.yml",
    "trusted-pr-auto.yml",
}
EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA = (
    "4d828e39ffaa129f3f825dead7dfb02f19f1651c"  # pragma: allowlist secret
)
EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (
    "7fdf0dc85375bc78561d531f95220cd877e30b3a"  # pragma: allowlist secret
)
EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA = (
    "49c3d4d79fd67602160b7752f1da345a7ad4dd61"  # pragma: allowlist secret
)
EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA = (
    "d809771ced237ec2d02d52b0eb29432f14c6a90b"  # pragma: allowlist secret
)
EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA = (
    "7e236900be3b05ab00b09d78b49007646432503e"  # pragma: allowlist secret
)
EXPECTED_PROTECTED_REMEDIATION_WORKFLOW_BLOB_SHA = (
    "1dd58588ea4833bee8b2c5c4bf86e24021baebd7"  # pragma: allowlist secret
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
_trusted_auto._base.ADDITIONAL_ALLOWED_ACTION_IDENTITIES.add("actions/create-github-app-token")


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
            "ci.yml: trigger set must be exactly pull_request/push/merge_group/workflow_dispatch"
        )
    if base._top_level_keys(base._top_level_block(text, "on")) != {
        "pull_request",
        "push",
        "merge_group",
        "workflow_dispatch",
    }:
        raise ValueError("ci.yml: unreviewed trigger authority is forbidden")

    for forbidden in (
        "TRUSTED_GATE_APP_CLIENT_ID",
        "TRUSTED_GATE_APP_PRIVATE_KEY",
        "${{ secrets.",
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
        "${{ secrets.",
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
        "      CI_SUBJECT_SHA: ${{ github.event_name == 'workflow_dispatch' && inputs.subject_sha || github.sha }}\n"
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
    for required_dispatch_guard in (
        '[[ ! "$EXPECTED_SUBJECT_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '[[ "$GITHUB_REF" != "refs/heads/main" ]]',
        '[[ "$EXPECTED_SUBJECT_REF" == "main" ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^dependabot/github_actions/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
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
        "triggers": ["merge_group", "pull_request", "push", "workflow_dispatch"],
        "subject": "event-sha-or-explicit-qualified-sha",
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
        "    if: github.event_name != 'workflow_dispatch' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)",
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
    )
    for fragment in ordinary_required:
        if fragment not in ordinary:
            raise ValueError(f"codeql.yml ordinary analysis invariant missing: {fragment}")

    qualified_required = (
        "    name: Exact-Subject CodeQL Analysis",
        "    if: github.event_name == 'workflow_dispatch'",
        "      actions: read",
        "      contents: read",
        "      security-events: write",
        "      - name: Bind trusted-main dispatch to exact analysis subject",
        "          EXPECTED_SUBJECT_SHA: ${{ inputs.subject_sha }}",
        "          EXPECTED_SUBJECT_REF: ${{ inputs.subject_ref }}",
        'test "$GITHUB_REF" = "refs/heads/main"',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/dependency-promotion-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
        '[[ "$EXPECTED_SUBJECT_REF" =~ ^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{12}$ ]]',
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
        "      - name: Analyze exact generated subject",
        "          ref: refs/heads/${{ inputs.subject_ref }}",
        "          sha: ${{ inputs.subject_sha }}",
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

    return {
        "triggers": ["pull_request", "push", "schedule", "workflow_dispatch"],
        "language": "python",
        "queries": "security-extended",
        "codeql_action_sha": next(iter(codeql_refs)),
        "codeql_major": EXPECTED_CODEQL_MAJOR,
        "codeql_tools_authority": "release-asset-sha256-verified-local-archive",
        "checkout_authority": "exact-reviewed-immutable-sha",
        "security_events_write": True,
        "workflow_dispatch_subject": "trusted-main-plus-explicit-ref-sha",
        "candidate_sarif_binding": "explicit-ref-plus-sha",
        "candidate_check_publication": "isolated-checks-write-after-exact-ref-revalidation",
        "merge_authority": "none",
        "status_write_authority": "none",
        "workflow_definition": "semantic-reviewed-v4-codeql-contract",
    }


def _verify_dependency_governance_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if "  pull_request_target:" in semantic:
        raise ValueError("dependency-governance.yml must not use pull_request_target")
    if base._workflow_structure_sha1(text) != EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "dependency-governance.yml non-action structure differs from reviewed dependency authority"
        )
    required = (
        "name: dependency-governance",
        "  pull_request:",
        "  workflow_run:",
        "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL, 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework']",
        "    types: [completed]",
        "  schedule:",
        "  workflow_dispatch:",
        "permissions:\n  contents: read",
        "    name: governance-self-test",
        "    if: github.event_name == 'pull_request'",
        "    name: govern-dependabot",
        "    if: github.event_name != 'pull_request'",
        "      actions: write",
        "      checks: write",
        "      contents: write",
        "      pull-requests: write",
        "      statuses: read",
        "          ref: ${{ github.event.repository.default_branch }}",
        "          persist-credentials: false",
        "          fetch-depth: 1",
        "      - name: Attempt one bounded transient recovery",
        "        run: python .github/scripts/dependency_recovery.py --recover",
        "      - name: Reconcile exact-subject Python dependency promotion",
        "        id: python_promotion",
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        "          python .github/scripts/dependency_promotion.py",
        "          --reconcile",
        "          --allow-merge",
        '          --github-output "$GITHUB_OUTPUT"',
        "      - name: Reconcile Dependabot action merge authority",
        "        if: steps.python_promotion.outputs.merged != 'true'",
        "          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
        '          case "$GITHUB_EVENT_NAME" in',
        "            workflow_run|schedule|workflow_dispatch) args+=(--allow-merge) ;;",
        '          python .github/scripts/dependency_governance.py "${args[@]}"',
        "printf 'PROMOTION_PYTHON311=%s\\n'",
        "printf 'PROMOTION_PYTHON314=%s\\n'",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(
                f"dependency-governance.yml missing reviewed authority invariant: {fragment}"
            )
    for forbidden in (
        "repository_dispatch:",
        "ubuntu-latest",
        "continue-on-error: true",
        "ref: ${{ github.event.pull_request.head.sha }}",
        "ref: ${{ github.event.workflow_run.head_sha }}",
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
    recovery = semantic.index("      - name: Attempt one bounded transient recovery")
    promotion = semantic.index("      - name: Reconcile exact-subject Python dependency promotion")
    reconcile = semantic.index("      - name: Reconcile Dependabot action merge authority")
    if not recovery < promotion < reconcile:
        raise ValueError(
            "dependency recovery, promotion, and action reconciliation are out of reviewed order"
        )
    return {
        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],
        "trusted_code_source": "default-branch-only-for-authority-job",
        "recovery_authority": "one-rerun-no-branch-mutation-no-merge",
        "python_dependency_authority": "signed-dependabot-intent-to-deterministic-lock-promotion",
        "merge_authority": "single-provenance-qualified-dependabot-controller",
        "trusted_status_authority": "read-only-observation-of-centralized-app-gate",
        "workflow_definition": "action-pin-normalized-reviewed-git-blob",
    }


def _verify_security_autoheal_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if base._workflow_structure_sha1(text) != EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "security-autoheal.yml non-action structure differs from reviewed security authority"
        )
    required = (
        "name: Security Auto-Heal",
        "  pull_request:",
        "  workflow_run:",
        "      - CodeQL",
        "      - 'CI — ƳƤ AI QA Automation Framework'",
        "      - 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'",
        "  schedule:",
        "  workflow_dispatch:",
        "permissions:\n  contents: read",
        "    name: security-autoheal-self-test",
        "  route-plan:",
        "    name: plan-codeql-autoheal-routes",
        "      actions: read",
        "      contents: read",
        "      pull-requests: read",
        "      security-events: read",
        "      artifact-id: ${{ steps.route-plan-artifact.outputs.artifact-id }}",
        "      artifact-digest: ${{ steps.route-plan-artifact.outputs.artifact-digest }}",
        "    name: reconcile-codeql-autoheal",
        "    needs: route-plan",
        "      actions: write",
        "      checks: write",
        "      contents: write",
        "      pull-requests: write",
        "      security-events: write",
        "      statuses: read",
        "          ref: ${{ github.event.repository.default_branch }}",
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
        "      - name: Restore exact-run route plan from prior read-only job",
        "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8",
        "          artifact-ids: ${{ needs.route-plan.outputs.artifact-id }}",
        "          path: ${{ runner.temp }}/security-autoheal-route-plan",
        "      - name: Reconcile exact-subject CodeQL remediations from persisted routes",
        "          --reconcile",
        "          --allow-merge",
        '          --route-plan "$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json"',
        "          --route-artifact-id ${{ needs.route-plan.outputs.artifact-id }}",
        "          --route-artifact-name security-autoheal-route-plan-${{ github.run_id }}-${{ github.run_attempt }}",
        "          --route-artifact-digest sha256:${{ needs.route-plan.outputs.artifact-digest }}",
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
    plan = semantic.index("      - name: Plan exact-main deterministic security routes")
    persist = semantic.index("      - name: Persist exact-run route plan before mutation")
    restore = semantic.index("      - name: Restore exact-run route plan from prior read-only job")
    reconcile = semantic.index(
        "      - name: Reconcile exact-subject CodeQL remediations from persisted routes"
    )
    if not plan < persist < restore < reconcile:
        raise ValueError(
            "security route planning, durable persistence, artifact restoration, and "
            "mutation reconciliation are out of reviewed order"
        )
    return {
        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],
        "trusted_code_source": "default-branch-only-for-authority-job",
        "repair_authority": (
            "read-only-plan-job-to-persisted-exact-run-route-before-write-authority"
        ),
        "merge_authority": "security-autoheal-namespace-only-after-exact-subject-proof",
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


_verify_automatic_workflow = _verify_ordinary_ci_workflow


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
            "  schedule:",
            '    - cron: "*/5 * * * *"',
        )
    )
    if base._semantic_text(base._top_level_block(text, "on")).strip("\n") != expected_on:
        raise ValueError("protected remediation workflow must be schedule-only")
    if base._top_level_keys(base._top_level_block(text, "on")) != {"schedule"}:
        raise ValueError("protected remediation workflow exposes an unreviewed trigger")
    base._verify_top_level_read_only_permissions(text, name="protected-security-remediation.yml")
    if base._top_level_keys(base._top_level_block(text, "jobs")) != {"reconcile"}:
        raise ValueError("protected remediation workflow must expose exactly one reconcile job")
    concurrency = base._semantic_text(base._top_level_block(text, "concurrency"))
    for fragment in (
        "  group: protected-security-remediation-scheduled-reconcile",
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
    if _trusted_auto._job_permissions(job) != {
        "actions": "read",
        "checks": "read",
        "contents": "read",
        "pull-requests": "read",
        "security-events": "read",
        "statuses": "read",
    }:
        raise ValueError("protected remediation native GitHub token must remain exactly read-only")
    required_job = (
        "    name: Independent Protected Remediation Reconcile",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 10",
        "    environment:\n      name: protected-remediation-author\n      deployment: false",
        "      - name: Checkout trusted default-branch control plane",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        '        run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        '          python-version: "3.11.16"',
        "      - name: Validate independent author identity configuration",
        '            "github-actions[bot]"|"dependabot[bot]"|"trusted-pr-gate[bot]") exit 1 ;;',
        "      - name: Mint dedicated protected-remediation author token",
        "      - name: Bind minted App to reviewed bot identity",
        '          test "${OBSERVED_APP_SLUG}[bot]" = "$EXPECTED_BOT_LOGIN"',
        "      - name: Reconcile protected security remediation",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          PROTECTED_REMEDIATION_APP_TOKEN: ${{ steps.author-app.outputs.token }}",
        "          python .github/scripts/protected_security_remediation.py --reconcile --allow-merge",
    )
    for fragment in required_job:
        if fragment not in job:
            raise ValueError(
                f"protected remediation reconcile is missing reviewed fragment: {fragment}"
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
    if semantic.count("actions/create-github-app-token@") != 1:
        raise ValueError("protected remediation must mint exactly one author App token")
    if semantic.count("${{ secrets.PROTECTED_REMEDIATION_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("protected remediation private key must have exactly one consumer")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_APP_CLIENT_ID }}") != 2:
        raise ValueError("protected remediation App client id must have exactly two consumers")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_BOT_LOGIN }}") != 3:
        raise ValueError("protected remediation bot login must have exactly three consumers")
    if semantic.count("${{ vars.PROTECTED_REMEDIATION_BOT_ID }}") != 2:
        raise ValueError("protected remediation bot id must have exactly two consumers")
    if semantic.count("${{ steps.author-app.outputs.token }}") != 1:
        raise ValueError("protected remediation App token must have exactly one execution consumer")
    if semantic.count("${{ steps.author-app.outputs.app-slug }}") != 1:
        raise ValueError("protected remediation App slug must be checked exactly once")
    if semantic.count("persist-credentials: false") != 1:
        raise ValueError("protected remediation checkout must disable persisted credentials")
    if semantic.count("ref: ${{ github.sha }}") != 1:
        raise ValueError(
            "protected remediation must checkout only the schedule's default-branch SHA"
        )
    return {
        "trigger": "schedule:5m",
        "trusted_definition": "default-branch-scheduled-workflow",
        "native_token": "read-only",
        "author_token": "distinct-app:contents-write+pull-requests-write",
        "status_authority": "none",
        "candidate_workflow_execution": "forbidden",
        "mutation": "exact-route+one-file+branch-pr-only",
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
    dependency_governance = _verify_dependency_governance_workflow(
        workflows["dependency-governance.yml"]
    )
    manual = base._verify_manual_workflow(workflows["manual-validation.yml"])
    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])
    security_autoheal = _verify_security_autoheal_workflow(workflows["security-autoheal.yml"])
    protected_remediation = _verify_protected_remediation_workflow(
        workflows["protected-security-remediation.yml"]
    )
    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(workflows["trusted-pr-auto.yml"])
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository workflow definitions satisfy deterministic CI authority invariants",
        "workflows": {
            "automatic": ordinary,
            "codeql": codeql,
            "dependency_governance": dependency_governance,
            "manual": manual,
            "protected_remediation": protected_remediation,
            "release_candidate": release_candidate,
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
                "Dependency governance is the sole autonomous Dependabot merge authority and consumes "
                "the App-owned Trusted PR Gate only after exact bot/provenance/check proofs; it does not "
                "hold App status-write credentials itself."
            ),
            (
                "The release-candidate workflow is manual, read-only, and non-publishing; its "
                "manifest/checksums are integrity evidence, not publisher identity, signing, "
                "deployment approval, or protected merge authority."
            ),
            (
                "Automatic Trusted PR Gate admission refuses protected changes for owner-routine PRs, "
                "while the finite governed bot lanes may cross protected roots only after lane-specific "
                "provenance proof; candidate validation remains read-only and secret-free until the reporter."
            ),
            (
                "Recognized Dependabot Actions, deterministic dependency-promotion, CodeQL auto-heal, and "
                "independently App-authored protected-remediation subjects are autonomously admitted by the "
                "centralized App gate after exact qualification "
                "and prospective-merge validation; unrecognized protected maintenance still requires the "
                "independent external one-shot gate."
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
