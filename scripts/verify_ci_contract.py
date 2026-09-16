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
    "release-candidate.yml",
    "security-autoheal.yml",
    "trusted-pr-auto.yml",
}
EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA = (
    "c5cf6a2615655c2d9381047e7474b760314b6fdc"  # pragma: allowlist secret
)
EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (
    "4a426cdf3d0e623009d146d6350af1a75a6be8b3"  # pragma: allowlist secret
)
EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA = (
    "fbe47dcf9a201dfb9da390b01e68f5b662689538"  # pragma: allowlist secret
)
EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA = (
    "9d09d68fe802e6e1c7a94933c14f7f9005e9a2a4"  # pragma: allowlist secret
)
EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA = (
    "158a4d0444eb46ddbd438aa2c7466a8b0dddc26f"  # pragma: allowlist secret
)
EXPECTED_CODEQL_MAJOR = 4
CODEQL_ACTION_RE = re.compile(
    r"^\s*uses:\s*(github/codeql-action/(?:init|analyze))@([0-9a-f]{40})"
    r"\s+#\s+v(\d+(?:\.\d+){0,2})\s*$",
    re.MULTILINE,
)
# Compatibility alias for adversarial tests and callers that imported the historical helper name.
EXPECTED_AUTOMATIC_WORKFLOW_BLOB_SHA = EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA

_trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
_trusted_auto._base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES


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
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError("ci.yml: trigger set must be exactly pull_request/push/merge_group/workflow_dispatch")
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
    if base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError(f"{name}: write permission is forbidden")
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

    supply_chain_raw = base._job_block(text, "supply-chain")
    supply_chain = base._semantic_text(supply_chain_raw)
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

    if base._git_blob_sha1(text) != EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "ci.yml bytes differ from the exact reviewed ordinary CI definition; "
            "exact reviewed automatic/trusted workflow definition is not satisfied"
        )

    return {
        "triggers": ["merge_group", "pull_request", "push", "workflow_dispatch"],
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "required_gate": "Required PR Gate",
        "quality_lanes": quality_lanes,
        "prebuild_authority": "exact-lock-and-build-authority-before-validation-installs",
        "dependency_install_count": dependency_install_count,
        "dependency_install_authority": "exact-reviewed-locks-preinstall-and-postinstall-revalidated",
        "project_install_count": project_install_count,
        "project_install_authority": "immediate-static-revalidation",
        "workflow_definition": "exact-reviewed-git-blob",
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
        "status_write_authority": "none",
        "protected_maintenance_authority": "external-trusted-gate-only",
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
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError("codeql.yml trigger set differs from the reviewed definition")
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
    required = (
        "name: CodeQL",
        "    name: CodeQL",
        "    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository",
        "      actions: read",
        "      contents: read",
        "      security-events: write",
        "    runs-on: ubuntu-24.04",
        "    timeout-minutes: 20",
        f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}",
        "          persist-credentials: false",
        "          languages: python",
        "          queries: security-extended",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(f"codeql.yml missing reviewed invariant: {fragment}")
    uses = base.ACTION_RE.findall(text)
    if len(uses) != 3:
        raise ValueError(
            "codeql.yml must contain exactly checkout, CodeQL init, and CodeQL analyze"
        )
    checkout = [item for item in uses if item[0] == "actions/checkout"]
    if (
        len(checkout) != 1
        or checkout[0][1].lower() != base.EXPECTED_ACTION_SHAS["actions/checkout"]
    ):
        raise ValueError("codeql.yml checkout action must use the reviewed immutable revision")
    codeql = CODEQL_ACTION_RE.findall(text)
    if len(codeql) != 2 or {item[0] for item in codeql} != {
        "github/codeql-action/init",
        "github/codeql-action/analyze",
    }:
        raise ValueError(
            "codeql.yml must use exactly one CodeQL init and one CodeQL analyze action"
        )
    codeql_refs = {item[1].lower() for item in codeql}
    codeql_versions = {item[2] for item in codeql}
    if len(codeql_refs) != 1:
        raise ValueError("CodeQL init and analyze must use the same immutable revision")
    if len(codeql_versions) != 1:
        raise ValueError("CodeQL init and analyze must declare the same reviewed version")
    version = next(iter(codeql_versions))
    if int(version.split(".", 1)[0]) != EXPECTED_CODEQL_MAJOR:
        raise ValueError("CodeQL action major version differs from the reviewed v4 authority")
    if semantic.count("security-events: write") != 1:
        raise ValueError("codeql.yml may write only one security-events permission")
    return {
        "triggers": ["pull_request", "push", "schedule", "workflow_dispatch"],
        "language": "python",
        "queries": "security-extended",
        "codeql_action_sha": next(iter(codeql_refs)),
        "codeql_major": EXPECTED_CODEQL_MAJOR,
        "checkout_authority": "exact-reviewed-immutable-sha",
        "security_events_write": True,
        "merge_authority": "none",
        "status_write_authority": "none",
        "workflow_definition": "semantic-reviewed-v4-codeql-contract",
    }


def _verify_dependency_governance_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if "  pull_request_target:" in semantic:
        raise ValueError("dependency-governance.yml must not use pull_request_target")
    if base._git_blob_sha1(text) != EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "dependency-governance.yml bytes differ from the exact reviewed dependency authority"
        )
    required = (
        "name: dependency-governance",
        "  pull_request:",
        "  workflow_run:",
        "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL]",
        "  schedule:",
        "  workflow_dispatch:",
        "permissions:\n  contents: read",
        "    name: governance-self-test",
        "    name: govern-dependabot",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "      actions: write",
        "      checks: read",
        "      contents: write",
        "      pull-requests: write",
        "      statuses: read",
        "          ref: ${{ github.event.repository.default_branch }}",
        "          persist-credentials: false",
        "      - name: Set up Python 3.11",
        "          python-version: '3.11.16'",
        "      - name: Capture Python 3.11 resolver",
        "printf 'PROMOTION_PYTHON311=%s\\n'",
        "      - name: Set up Python 3.14",
        "          python-version: '3.14.7'",
        "      - name: Capture Python 3.14 resolver",
        "printf 'PROMOTION_PYTHON314=%s\\n'",
        "      - name: Attempt one bounded transient recovery",
        "        run: python .github/scripts/dependency_recovery.py --recover",
        "      - name: Mint dedicated Trusted PR Gate token",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Reconcile exact-subject Python dependency promotion",
        "        run: python .github/scripts/dependency_promotion.py --reconcile --allow-merge",
        "      - name: Reconcile Dependabot action merge authority",
        '          python .github/scripts/dependency_governance.py "${args[@]}"',
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
    ):
        if forbidden in semantic:
            raise ValueError(
                f"dependency-governance.yml contains forbidden authority token: {forbidden}"
            )
    if semantic.count('"statuses":"write"') != 1 or semantic.count("statuses: write") != 0:
        raise ValueError("native workflow authority must remain status-read-only")
    recovery = semantic.index("      - name: Attempt one bounded transient recovery")
    mint = semantic.index("      - name: Mint dedicated Trusted PR Gate token")
    promotion = semantic.index("      - name: Reconcile exact-subject Python dependency promotion")
    actions = semantic.index("      - name: Reconcile Dependabot action merge authority")
    if not recovery < mint < promotion < actions:
        raise ValueError(
            "dependency recovery, trusted-token minting, Python promotion, and action reconciliation are out of order"
        )
    return {
        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],
        "trusted_code_source": "default-branch-only-for-authority-job",
        "recovery_authority": "one-rerun-no-branch-mutation-no-merge",
        "python_merge_authority": "signed-dependabot-source-plus-deterministic-lock-promotion",
        "action_merge_authority": "single-provenance-qualified-dependabot-controller",
        "trusted_status_authority": "dedicated-app-token-after-exact-subject-proof",
        "workflow_definition": "exact-reviewed-git-blob",
    }


def _verify_security_autoheal_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    semantic = base._semantic_text(text)
    if base._git_blob_sha1(text) != EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA:
        raise ValueError("security-autoheal.yml bytes differ from the exact reviewed security authority")
    required = (
        "name: Security Auto-Heal",
        "  pull_request:",
        "  workflow_run:",
        "      - CodeQL",
        "      - 'CI — ƳƤ AI QA Automation Framework'",
        "  schedule:",
        "  workflow_dispatch:",
        "permissions:\n  contents: read",
        "    name: security-autoheal-self-test",
        "    name: reconcile-codeql-autoheal",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "      actions: write",
        "      checks: read",
        "      contents: write",
        "      pull-requests: write",
        "      security-events: write",
        "      statuses: read",
        "          ref: ${{ github.event.repository.default_branch }}",
        "          persist-credentials: false",
        "      - name: Mint dedicated Trusted PR Gate token",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Reconcile exact-subject CodeQL remediations",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",
        "        run: python .github/scripts/security_autoheal.py --reconcile --allow-merge",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(f"security-autoheal.yml missing reviewed authority invariant: {fragment}")
    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "ubuntu-latest",
        "continue-on-error: true",
        "id-token: write",
    ):
        if forbidden in semantic:
            raise ValueError(f"security-autoheal.yml contains forbidden authority token: {forbidden}")
    if semantic.count('"statuses":"write"') != 1 or semantic.count("statuses: write") != 0:
        raise ValueError("security auto-heal native workflow authority must remain status-read-only")
    return {
        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],
        "trusted_code_source": "default-branch-only-for-authority-job",
        "repair_authority": "code-owned-rule-and-path-bounded-generated-prs",
        "merge_authority": "security-autoheal-namespace-only-after-exact-subject-proof",
        "trusted_status_authority": "dedicated-app-token-after-codeql-remediation-proof",
        "workflow_definition": "exact-reviewed-git-blob",
    }


def _verify_release_candidate_workflow(text: str) -> dict[str, Any]:
    base = _trusted_auto._base
    name = "release-candidate.yml"
    semantic = base._semantic_text(text)
    if base._git_blob_sha1(text) != EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA:
        raise ValueError("release-candidate.yml bytes differ from the exact reviewed definition")

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
        "workflow_definition": "exact-reviewed-git-blob",
    }


_verify_automatic_workflow = _verify_ordinary_ci_workflow


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    base = _trusted_auto._base
    _verify_frozen_trusted_auto_extension()
    _trusted_auto._verify_frozen_base()
    _trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
    base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES

    snapshots = base._read_workflow_set(root / ".github" / "workflows")
    workflows = {name: snapshot.text for name, snapshot in snapshots.items()}
    action_workflows = {name: text for name, text in workflows.items() if name != "codeql.yml"}
    actions = base._verify_action_revisions(action_workflows)
    ordinary = _verify_ordinary_ci_workflow(workflows["ci.yml"])
    codeql = _verify_codeql_workflow(workflows["codeql.yml"])
    dependency_governance = _verify_dependency_governance_workflow(
        workflows["dependency-governance.yml"]
    )
    manual = base._verify_manual_workflow(workflows["manual-validation.yml"])
    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])
    security_autoheal = _verify_security_autoheal_workflow(workflows["security-autoheal.yml"])
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
                "Dependency governance is the sole autonomous Dependabot merge authority and uses "
                "the dedicated Trusted PR Gate credential only after exact bot/provenance/check proofs."
            ),
            (
                "The release-candidate workflow is manual, read-only, and non-publishing; its "
                "manifest/checksums are integrity evidence, not publisher identity, signing, "
                "deployment approval, or protected merge authority."
            ),
            (
                "Automatic Trusted PR Gate admission intentionally refuses any PR that changes a "
                "protected authority root; its candidate validation remains read-only and "
                "secret-free until the final trusted reporter."
            ),
            (
                "Protected maintenance is authorized only by the independently deployed external "
                "Trusted PR Gate with exact subject/protected-transition policy; repository "
                "repository_dispatch is not a maintenance authority."
            ),
            (
                "The trusted-pr-gate Environment/App credential remains required by the routine "
                "automatic reporter and must not be retired while that live path depends on it."
            ),
            (
                "Repository code cannot attest external deployment, one-shot policy, Environment "
                "protection, App installation, ruleset binding, or hosted infrastructure state; "
                "those require live external evidence."
            ),
            (
                "Trusted PR Gate is published on the PR head after exact head/base/merge "
                "revalidation, so protected-branch enforcement must remain strict/up-to-date."
            ),
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    verify_ci_contract(root)
    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "ci-contract"}, sort_keys=True))


if __name__ == "__main__":
    main()
