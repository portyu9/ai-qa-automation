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
# helpers directly. The frozen trusted-auto extension itself re-exports the hardened base.
for _export_name in dir(_trusted_auto):
    if not _export_name.startswith("__"):
        globals()[_export_name] = getattr(_trusted_auto, _export_name)
del _export_name

EXPECTED_WORKFLOW_NAMES = {
    "ci.yml",
    "manual-validation.yml",
    "trusted-pr-auto.yml",
    "trusted-pr-evidence.yml",
}
EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA = (
    "15c2492c28c571f7a5a0d20600f1a6975ebb4151"  # pragma: allowlist secret
)
EXPECTED_TRUSTED_EVIDENCE_WORKFLOW_BLOB_SHA = (
    "bcec60a3890fe80cb02d90c6cf1b42a7f91525cd"  # pragma: allowlist secret
)
EXPECTED_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA = (
    "d7faa4803d0d75f0b9e10c2f65cf6bbef78cce65"  # pragma: allowlist secret
)
EXPECTED_AUTO_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA = (
    "387a3409c482d2360f03916eebd064c441482f5d"  # pragma: allowlist secret
)
TRUSTED_EVIDENCE_WORKFLOW = "CI — ƳƤ AI QA Automation Framework"

_trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
_trusted_auto._base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES


def _verify_frozen_trusted_auto_extension() -> None:
    path = Path(_trusted_auto.__file__)
    if path.is_symlink() or not path.is_file():
        raise ValueError("trusted-auto CI contract extension must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA:
        raise ValueError("trusted-auto CI contract extension differs from the frozen definition")


def _verify_frozen_script(root: Path, name: str, expected_blob: str, label: str) -> None:
    path = root / "scripts" / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != expected_blob:
        raise ValueError(f"{label} differs from the frozen reviewed definition")


def _verify_trusted_evidence_workflow(text: str) -> dict[str, Any]:
    semantic = _trusted_auto._base._semantic_text(text)
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_EVIDENCE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "trusted-pr-evidence.yml bytes differ from the exact reviewed automatic evidence definition"
        )

    on_block = _trusted_auto._base._semantic_text(
        _trusted_auto._base._top_level_block(text, "on")
    ).strip("\n")
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            f'    workflows: ["{TRUSTED_EVIDENCE_WORKFLOW}"]',
            "    types: [completed]",
        )
    )
    if on_block != expected_on:
        raise ValueError(
            "trusted-pr-evidence.yml must be triggered only by completed ordinary CI workflow_run"
        )

    permissions = _trusted_auto._base._permissions(
        _trusted_auto._base._top_level_block(text, "permissions")
    )
    if permissions != {"actions": "read", "contents": "read", "pull-requests": "read"}:
        raise ValueError("trusted-pr-evidence.yml top-level token must be exactly read-only")
    if _trusted_auto._base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError(
            "trusted-pr-evidence.yml native GitHub token must never request write authority"
        )
    for forbidden in (
        "repository_dispatch:",
        "pull_request_target:",
        "workflow_dispatch:",
        "github.event.client_payload",
        "continue-on-error: true",
        "ubuntu-latest",
        "playwright install",
        "sudo ",
        "apt-get ",
        "apt install ",
        "${{ secrets.GITHUB_TOKEN }}",
        "ref: ${{ github.event.workflow_run.head_sha }}",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"trusted-pr-evidence.yml contains forbidden authority token: {forbidden}"
            )
    if _trusted_auto._base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError("trusted-pr-evidence.yml dependency caching is forbidden")
    if semantic.count("ref: ${{ github.sha }}") != 3:
        raise ValueError("automatic protected evidence must checkout only trusted main three times")
    if semantic.count("persist-credentials: false") != 3:
        raise ValueError("every automatic protected evidence checkout must disable credentials")
    if semantic.count("python scripts/auto_trusted_preflight.py") != 2:
        raise ValueError("protected admission must be independently resolved exactly twice")
    if semantic.count("python scripts/auto_trusted_evidence.py") != 2:
        raise ValueError("protected evidence must be admitted and freshly revalidated exactly twice")
    if semantic.count("EVIDENCE_RUN_ID: ${{ github.event.workflow_run.id }}") != 2:
        raise ValueError("both evidence passes must bind to the exact originating CI run ID")
    if semantic.count(
        "PROTECTED_MANIFEST_JSON: ${{ needs.preflight.outputs.protected_changes_json }}"
    ) != 2:
        raise ValueError("both evidence passes must consume the trusted preflight object manifest")

    preflight = _trusted_auto._base._semantic_text(
        _trusted_auto._base._job_block(text, "preflight")
    )
    required_preflight = (
        "    name: Automatic Protected-Change Admission",
        "    if: ${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success' }}",
        "          ref: ${{ github.sha }}",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python scripts/auto_trusted_preflight.py \\",
        '            --event "$GITHUB_EVENT_PATH" \\',
        '            --github-output "$GITHUB_OUTPUT"',
        '          test "$TRUSTED_SHA" = "$GITHUB_SHA"',
    )
    for fragment in required_preflight:
        if fragment not in preflight:
            raise ValueError(f"automatic protected preflight is missing reviewed fragment: {fragment}")
    if "${{ secrets." in preflight:
        raise ValueError("automatic protected preflight must be completely secret-free")

    admission = _trusted_auto._base._semantic_text(
        _trusted_auto._base._job_block(text, "evidence-admission")
    )
    required_admission = (
        "    name: Automatic Exact-Run Protected Evidence Admission",
        "    if: ${{ needs.preflight.result == 'success' && needs.preflight.outputs.eligible == 'false' }}",
        "          ref: ${{ github.sha }}",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          EVIDENCE_RUN_ID: ${{ github.event.workflow_run.id }}",
        "          python scripts/auto_trusted_evidence.py \\",
        '            --expected-merge-sha "$EXPECTED_MERGE_SHA" \\',
        '            --protected-manifest-json "$PROTECTED_MANIFEST_JSON" \\',
        '            --evidence-run-id "$EVIDENCE_RUN_ID" \\',
        '            --github-output "$GITHUB_OUTPUT"',
    )
    for fragment in required_admission:
        if fragment not in admission:
            raise ValueError(f"automatic protected evidence admission is missing: {fragment}")
    if "${{ secrets." in admission:
        raise ValueError("automatic protected evidence admission must be completely secret-free")

    reporter = _trusted_auto._base._semantic_text(
        _trusted_auto._base._job_block(text, "trusted-status")
    )
    required_reporter = (
        "    name: Automatic Protected PR Gate Reporter",
        "    if: ${{ always() && needs.preflight.result == 'success' && needs.preflight.outputs.eligible == 'false' && needs.evidence-admission.result == 'success' }}",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "    permissions:\n      actions: read\n      contents: read\n      pull-requests: read",
        "      - name: Re-resolve automatic protected admission",
        "      - name: Require exact final preflight identity",
        '          test "$FINAL_ELIGIBLE" = "false"',
        '          test "$FINAL_PROTECTED_CHANGES" = "$EXPECTED_PROTECTED_CHANGES"',
        "      - name: Revalidate exact originating pull-request evidence",
        "          EVIDENCE_RUN_ID: ${{ github.event.workflow_run.id }}",
        "          EXPECTED_EVIDENCE_RUN_ID: ${{ needs.evidence-admission.outputs.evidence_run_id }}",
        '          test "$EVIDENCE_RUN_ID" = "$EXPECTED_EVIDENCE_RUN_ID"',
        "      - name: Mint dedicated Trusted PR Gate token",
        "          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Publish automatic exact-evidence trusted status",
        "          GITHUB_TOKEN: ${{ steps.trusted-app.outputs.token }}",
        "          python scripts/auto_trusted_report.py \\",
        '            --job-results-json \'{"validation":"success"}\' \\',
        '            --target-url "${{ needs.evidence-admission.outputs.evidence_target_url }}"',
    )
    for fragment in required_reporter:
        if fragment not in reporter:
            raise ValueError(f"automatic protected evidence reporter is missing: {fragment}")
    if semantic.count("${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("trusted evidence App private key must have exactly one consumer")
    if semantic.count("${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}") != 1:
        raise ValueError("trusted evidence App client ID must have exactly one consumer")
    if "${{ secrets." in semantic.replace(reporter, ""):
        raise ValueError("trusted evidence environment secrets must be isolated to reporter")

    revalidate_position = reporter.index(
        "      - name: Revalidate exact originating pull-request evidence"
    )
    mint_position = reporter.index("      - name: Mint dedicated Trusted PR Gate token")
    publish_position = reporter.index("      - name: Publish automatic exact-evidence trusted status")
    if not revalidate_position < mint_position < publish_position:
        raise ValueError("automatic protected evidence authority steps are out of reviewed order")

    return {
        "trigger": f"workflow_run:{TRUSTED_EVIDENCE_WORKFLOW}",
        "trusted_definition": "default-branch-owned-automatic-protected-evidence-workflow",
        "candidate_execution": "none",
        "evidence_subject": "exact-originating-successful-pull-request-ci-bound-to-live-head-base-merge-and-persisted-tree",
        "protected_authority": "trusted-main-derived-exact-object-manifest-plus-owner-originated-same-repository-run",
        "terminal_revalidation": "fresh-preflight-and-exact-run-evidence-before-app-mint-plus-live-subject-report",
        "status_writer": "dedicated-github-app",
        "workflow_definition": "exact-reviewed-git-blob",
        "evidence_verifier": "exact-reviewed-git-blob",
        "automatic_evidence_verifier": "exact-reviewed-git-blob",
    }


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    _verify_frozen_trusted_auto_extension()
    _trusted_auto._verify_frozen_base()
    _trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
    _trusted_auto._base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES

    result = _trusted_auto._base.verify_ci_contract(root)
    snapshots = _trusted_auto._base._read_workflow_set(root / ".github" / "workflows")
    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(
        snapshots["trusted-pr-auto.yml"].text
    )
    trusted_evidence = _verify_trusted_evidence_workflow(snapshots["trusted-pr-evidence.yml"].text)
    _verify_frozen_script(
        root,
        "trusted_pr_evidence.py",
        EXPECTED_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA,
        "trusted PR evidence verifier",
    )
    _verify_frozen_script(
        root,
        "auto_trusted_evidence.py",
        EXPECTED_AUTO_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA,
        "automatic trusted evidence verifier",
    )
    result["workflows"]["trusted_auto"] = trusted_auto
    result["workflows"]["trusted_evidence"] = trusted_evidence
    result["limitations"].append(
        "Routine same-repository PRs with unchanged protected authority roots use full default-branch-owned trusted re-execution; protected same-repository PRs use automatic exact-run evidence promotion instead of a second owner dispatch."
    )
    result["limitations"].append(
        "Automatic protected evidence promotion is restricted to owner-originated same-repository pull_request CI and requires live head/base/merge identity, an exact trusted-main-derived protected-object manifest, required job success, a digest-verified supply-chain artifact, and a persisted build manifest whose commit and tree match the live prospective merge."
    )
    result["limitations"].append(
        "Repository source can verify the workflow_run designs but cannot prove external Actions Policy or trusted Environment/App configuration until live runs are observed."
    )
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
