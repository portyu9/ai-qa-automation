from __future__ import annotations

import importlib.util
import json
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
    "manual-validation.yml",
    "release-candidate.yml",
    "trusted-pr-auto.yml",
}
EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA = (
    "9f85471d3c8f27a134b60274a248d2bc8a654d06"  # pragma: allowlist secret
)
EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (
    "66c0bf8aee2633bfb51c83029b0251f2d81dae29"  # pragma: allowlist secret
)
EXPECTED_RELEASE_CANDIDATE_WORKFLOW_BLOB_SHA = (
    "6600d9a798b48da3a63be8865bfccac52186eb81"  # pragma: allowlist secret
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
        )
    )
    on_block = base._semantic_text(base._top_level_block(text, "on")).strip("\n")
    if on_block != expected_on:
        raise ValueError("ci.yml: trigger set must be exactly pull_request/push/merge_group")
    if base._top_level_keys(base._top_level_block(text, "on")) != {
        "pull_request",
        "push",
        "merge_group",
    }:
        raise ValueError("ci.yml: unreviewed trigger authority is forbidden")

    # Secrets and the legacy App credential are independently forbidden authority even if
    # their injection also perturbs the exact reviewed environment block.
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
        "workflow_dispatch:",
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
        "triggers": ["merge_group", "pull_request", "push"],
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
        "ubuntu-latest",
        "pip install --upgrade",
        " --editable",
        " -e .",
    ):
        if forbidden in semantic:
            raise ValueError(f"release-candidate.yml contains forbidden authority token: {forbidden}")
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
        f"uses: actions/setup-python@{base.EXPECTED_ACTION_SHAS['actions/setup-python']}",
        'python-version: "3.11.16"',
        "python scripts/verify_release_candidate.py",
        '--expected-ref "$GITHUB_REF"',
        "python scripts/verify_build_authority.py",
        "python -m pip install --require-hashes -r requirements/build-py311.lock",
        "SOURCE_DATE_EPOCH: \"315532800\"",
        'archive --format=tar "$RELEASE_SUBJECT_SHA"',
        "cmp -s artifacts/release/build-authority-archive-a.json artifacts/release/build-authority-archive-b.json",
        '--wheel-a "${wheel_a[0]}"',
        '--wheel-b "${wheel_b[0]}"',
        "--output artifacts/release/release-manifest.json",
        "/usr/bin/sha256sum",
        f"uses: actions/upload-artifact@{base.EXPECTED_ACTION_SHAS['actions/upload-artifact']}",
        "name: release-candidate-evidence",
        "if-no-files-found: error",
        "retention-days: 30",
    )
    for snippet in required:
        if snippet not in semantic:
            raise ValueError(f"release-candidate.yml missing reviewed invariant: {snippet}")
    if semantic.count(f"uses: actions/checkout@{base.EXPECTED_ACTION_SHAS['actions/checkout']}") != 1:
        raise ValueError("release-candidate.yml must have exactly one exact-subject checkout")
    if semantic.count("python scripts/verify_release_candidate.py") != 2:
        raise ValueError("release-candidate.yml must verify identity before and after package build")
    if semantic.count("python -m pip wheel --no-deps --no-build-isolation") != 2:
        raise ValueError("release-candidate.yml must build exactly two reviewed wheels")
    if semantic.count("python scripts/verify_build_authority.py --root") != 2:
        raise ValueError("release-candidate.yml must independently verify both archive roots")

    return {
        "trigger": "workflow_dispatch",
        "source_ref": "refs/heads/main",
        "subject": "github.sha",
        "release_identity": "explicit-vMAJOR.MINOR.PATCH/static-project-version",
        "builds": 2,
        "package_reproducibility": "byte-identical-wheel-required",
        "build_authority": "hash-locked-and-archive-revalidated",
        "evidence": "canonical-manifest-plus-sha256-checksums",
        "permissions": "contents:read",
        "publishing_authority": "none",
        "signature_claim": "none",
        "merge_authority": "none",
        "workflow_definition": "exact-reviewed-git-blob",
    }


# Preserve the long-standing helper name for adversarial callers while changing its authority
# contract from ordinary+owner-dispatch to ordinary CI only.
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
    actions = base._verify_action_revisions(workflows)
    ordinary = _verify_ordinary_ci_workflow(workflows["ci.yml"])
    manual = base._verify_manual_workflow(workflows["manual-validation.yml"])
    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])
    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(workflows["trusted-pr-auto.yml"])
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository workflow definitions satisfy deterministic CI authority invariants",
        "workflows": {
            "automatic": ordinary,
            "manual": manual,
            "release_candidate": release_candidate,
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
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
