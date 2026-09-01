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
    "6f79df6ec3c280ba2adf314f08fa461550b6bdba"  # pragma: allowlist secret
)
EXPECTED_TRUSTED_EVIDENCE_WORKFLOW_BLOB_SHA = (
    "7cf510e5e345feb72f3e6e5e28d4029079db1876"  # pragma: allowlist secret
)
EXPECTED_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA = (
    "d7faa4803d0d75f0b9e10c2f65cf6bbef78cce65"  # pragma: allowlist secret
)
TRUSTED_EVIDENCE_EVENT = "trusted-pr-evidence-authorization"

_trusted_auto.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
_trusted_auto._base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES


def _verify_frozen_trusted_auto_extension() -> None:
    path = Path(_trusted_auto.__file__)
    if path.is_symlink() or not path.is_file():
        raise ValueError("trusted-auto CI contract extension must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_AUTO_EXTENSION_BLOB_SHA:
        raise ValueError("trusted-auto CI contract extension differs from the frozen definition")


def _verify_frozen_trusted_evidence_script(root: Path) -> None:
    path = root / "scripts" / "trusted_pr_evidence.py"
    if path.is_symlink() or not path.is_file():
        raise ValueError("trusted PR evidence verifier must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_EVIDENCE_SCRIPT_BLOB_SHA:
        raise ValueError("trusted PR evidence verifier differs from the frozen reviewed definition")


def _verify_trusted_evidence_workflow(text: str) -> dict[str, Any]:
    semantic = _trusted_auto._base._semantic_text(text)
    if _trusted_auto._base._git_blob_sha1(text) != EXPECTED_TRUSTED_EVIDENCE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "trusted-pr-evidence.yml bytes differ from the exact reviewed evidence authorization definition"
        )

    on_block = _trusted_auto._base._semantic_text(
        _trusted_auto._base._top_level_block(text, "on")
    ).strip("\n")
    expected_on = "\n".join(
        (
            "on:",
            "  repository_dispatch:",
            f"    types: [{TRUSTED_EVIDENCE_EVENT}]",
        )
    )
    if on_block != expected_on:
        raise ValueError(
            "trusted-pr-evidence.yml must be triggered only by the reviewed owner evidence event"
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
        "pull_request_target:",
        "workflow_run:",
        "workflow_dispatch:",
        "continue-on-error: true",
        "ubuntu-latest",
        "playwright install",
        "sudo ",
        "apt-get ",
        "apt install ",
        "${{ secrets.GITHUB_TOKEN }}",
        "ref: ${{ github.event.client_payload.expected_merge_sha }}",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"trusted-pr-evidence.yml contains forbidden authority token: {forbidden}"
            )
    if _trusted_auto._base.CACHE_CONFIGURATION_RE.search(semantic):
        raise ValueError("trusted-pr-evidence.yml dependency caching is forbidden")
    if semantic.count("ref: ${{ github.sha }}") != 2:
        raise ValueError("trusted evidence authorization must checkout only trusted main twice")
    if semantic.count("persist-credentials: false") != 2:
        raise ValueError("every trusted evidence checkout must disable persisted credentials")
    if "needs.evidence-admission.outputs.evidence_run_id" not in semantic:
        raise ValueError("trusted evidence reporter must bind to the admitted evidence run")
    if semantic.count("python scripts/trusted_pr_evidence.py") != 2:
        raise ValueError("trusted evidence must be admitted and freshly revalidated exactly twice")
    if (
        semantic.count(
            "PROTECTED_MANIFEST_JSON: ${{ toJSON(github.event.client_payload.protected_manifest) }}"
        )
        != 2
    ):
        raise ValueError("protected manifest must be supplied to both evidence admission passes")

    admission = _trusted_auto._base._semantic_text(
        _trusted_auto._base._job_block(text, "evidence-admission")
    )
    required_admission = (
        "    name: Trusted Exact-Subject Evidence Admission",
        "    if: ${{ github.ref == 'refs/heads/main' && github.actor == github.repository_owner }}",
        "          ref: ${{ github.sha }}",
        "          GITHUB_TOKEN: ${{ github.token }}",
        '          test "$AUTHORIZED" = "true"',
        "          python scripts/trusted_pr_evidence.py \\",
        '            --expected-merge-sha "$EXPECTED_MERGE_SHA" \\',
        '            --protected-manifest-json "$PROTECTED_MANIFEST_JSON" \\',
        '            --github-output "$GITHUB_OUTPUT"',
    )
    for fragment in required_admission:
        if fragment not in admission:
            raise ValueError(f"trusted evidence admission is missing reviewed fragment: {fragment}")
    if "${{ secrets." in admission:
        raise ValueError("trusted evidence admission must be completely secret-free")

    reporter = _trusted_auto._base._semantic_text(
        _trusted_auto._base._job_block(text, "trusted-status")
    )
    required_reporter = (
        "    name: Trusted PR Evidence Gate Reporter",
        "    if: ${{ always() && needs.evidence-admission.result == 'success' && github.ref == 'refs/heads/main' && github.actor == github.repository_owner }}",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "    permissions:\n      actions: read\n      contents: read\n      pull-requests: read",
        "      - name: Revalidate exact pull-request evidence",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          EXPECTED_EVIDENCE_RUN_ID: ${{ needs.evidence-admission.outputs.evidence_run_id }}",
        '          evidence_json="$(python scripts/trusted_pr_evidence.py \\',
        '          test "$observed_run_id" = "$EXPECTED_EVIDENCE_RUN_ID"',
        "      - name: Mint dedicated Trusted PR Gate token",
        "          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Publish exact-evidence trusted status",
        "          GITHUB_TOKEN: ${{ steps.trusted-app.outputs.token }}",
        "          python scripts/trusted_pr_control.py report \\",
        '            --job-results-json \'{"validation":"success"}\' \\',
        '            --target-url "${{ needs.evidence-admission.outputs.evidence_target_url }}"',
    )
    for fragment in required_reporter:
        if fragment not in reporter:
            raise ValueError(f"trusted evidence reporter is missing reviewed fragment: {fragment}")
    if semantic.count("${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("trusted evidence App private key must have exactly one consumer")
    if semantic.count("${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}") != 1:
        raise ValueError("trusted evidence App client ID must have exactly one consumer")
    if "${{ secrets." in semantic.replace(reporter, ""):
        raise ValueError("trusted evidence environment secrets must be isolated to reporter")

    revalidate_position = reporter.index("      - name: Revalidate exact pull-request evidence")
    mint_position = reporter.index("      - name: Mint dedicated Trusted PR Gate token")
    publish_position = reporter.index("      - name: Publish exact-evidence trusted status")
    if not revalidate_position < mint_position < publish_position:
        raise ValueError("trusted evidence reporter authority steps are out of reviewed order")

    return {
        "trigger": f"repository_dispatch:{TRUSTED_EVIDENCE_EVENT}",
        "trusted_definition": "default-branch-owner-dispatch-workflow",
        "candidate_execution": "none",
        "evidence_subject": "successful-pull-request-ci-bound-to-live-head-base-and-persisted-merge-manifest",
        "protected_authority": "exact-owner-provided-object-manifest",
        "terminal_revalidation": "fresh-evidence-admission-before-app-mint-plus-live-subject-report",
        "status_writer": "dedicated-github-app",
        "workflow_definition": "exact-reviewed-git-blob",
        "evidence_verifier": "exact-reviewed-git-blob",
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
    _verify_frozen_trusted_evidence_script(root)
    result["workflows"]["trusted_auto"] = trusted_auto
    result["workflows"]["trusted_evidence"] = trusted_evidence
    result["limitations"].append(
        "Automatic trusted admission intentionally refuses any PR that changes a protected authority root; protected maintenance changes require explicit owner authorization."
    )
    result["limitations"].append(
        "The owner evidence-authorization fallback promotes only a successful pull_request CI run after live head/base/merge, exact protected-object admission, and digest-verified persisted build-manifest evidence bound to the authorized merge SHA; it intentionally does not execute candidate bytes under privileged authority."
    )
    result["limitations"].append(
        "Repository source can verify the workflow_run and evidence-authorization designs but cannot prove external Actions Policy or trusted Environment/App configuration until live runs are observed."
    )
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
