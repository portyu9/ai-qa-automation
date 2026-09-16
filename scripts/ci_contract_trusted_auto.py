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
    "b3a24448e8e233768b5a17a567d3d1262d6a0927"  # pragma: allowlist secret
)
EXPECTED_BASE_VERIFIER_BLOB_SHA = (
    "afe86e3912b4f6ca44f86473262eb074f4851e91"  # pragma: allowlist secret
)
TRUSTED_AUTO_WORKFLOW_NAME = "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"
TRUSTED_AUTO_SOURCE_WORKFLOW = "CI — ƳƤ AI QA Automation Framework"
TRUSTED_AUTO_PROTECTED_PATHS = (
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


def _verify_frozen_base() -> None:
    path = Path(_base.__file__)
    if path.is_symlink() or not path.is_file():
        raise ValueError("CI contract base verifier must be a regular non-symlink file")
    text = path.read_text(encoding="utf-8")
    if _base._git_blob_sha1(text) != EXPECTED_BASE_VERIFIER_BLOB_SHA:
        raise ValueError("CI contract base verifier differs from the frozen hardened definition")


def _verify_trusted_auto_workflow(text: str) -> dict[str, Any]:
    semantic = _base._semantic_text(text)
    if _base._git_blob_sha1(text) != EXPECTED_TRUSTED_AUTO_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "trusted-pr-auto.yml bytes differ from the exact reviewed automatic trust definition"
        )

    on_block = _base._semantic_text(_base._top_level_block(text, "on")).strip("\n")
    expected_on = "\n".join(
        (
            "on:",
            "  workflow_run:",
            f'    workflows: ["{TRUSTED_AUTO_SOURCE_WORKFLOW}"]',
            "    types: [completed]",
        )
    )
    if on_block != expected_on:
        raise ValueError("trusted-pr-auto.yml must be triggered only by completed reviewed CI runs")

    permissions = _base._permissions(_base._top_level_block(text, "permissions"))
    if permissions != {"actions": "read", "contents": "read", "pull-requests": "read"}:
        raise ValueError("trusted-pr-auto.yml top-level token must be exactly read-only")
    if _base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError("trusted-pr-auto.yml native token must not have write permissions")
    for forbidden in (
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_dispatch:",
        "push:",
        "schedule:",
        "contents: write",
        "pull-requests: write",
        "statuses: write",
        "checks: write",
        "id-token: write",
        "ubuntu-latest",
        "continue-on-error: true",
        "secrets: inherit",
    ):
        if forbidden in semantic:
            raise ValueError(f"trusted-pr-auto.yml contains forbidden authority token: {forbidden}")

    required = (
        "    name: Trusted PR Gate Reporter",
        "    if: github.event.workflow_run.conclusion == 'success'",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "      actions: read",
        "      contents: read",
        "      pull-requests: read",
        f"uses: actions/checkout@{_base.EXPECTED_ACTION_SHAS['actions/checkout']}",
        "          ref: ${{ github.event.repository.default_branch }}",
        "          persist-credentials: false",
        "          fetch-depth: 1",
        "      - name: Qualify exact successful CI subject",
        "        id: preflight",
        "        env:\n          GITHUB_TOKEN: ${{ github.token }}",
        "        run: >-",
        "          python scripts/auto_trusted_preflight.py",
        "          --event $GITHUB_EVENT_PATH",
        "          --github-output $GITHUB_OUTPUT",
        "      - name: Stop automatic admission for protected changes",
        "        if: steps.preflight.outputs.eligible != 'true'",
        "        run: |",
        "          echo 'Automatic trusted admission denied for protected transition.'",
        "          exit 1",
        "      - name: Mint dedicated Trusted PR Gate token",
        "        id: trusted-app",
        "        env:",
        "          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}",
        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        '"permissions":{"contents":"read","pull_requests":"read","statuses":"write"}',
        "      - name: Publish exact-subject Trusted PR Gate",
        "        env:",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",
        "        run: >-",
        "          python scripts/auto_trusted_report.py",
        "          --expected-pr-number ${{ steps.preflight.outputs.pr_number }}",
        "          --expected-head-sha ${{ steps.preflight.outputs.head_sha }}",
        "          --expected-base-sha ${{ steps.preflight.outputs.base_sha }}",
        "          --expected-merge-sha ${{ steps.preflight.outputs.merge_sha }}",
        "          --job-results-json ${{ toJSON(github.event.workflow_run.conclusion) }}",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(f"trusted-pr-auto.yml missing reviewed invariant: {fragment}")

    checkout = f"uses: actions/checkout@{_base.EXPECTED_ACTION_SHAS['actions/checkout']}"
    if semantic.count(checkout) != 1:
        raise ValueError("trusted-pr-auto.yml must contain exactly one reviewed checkout")
    if semantic.count("TRUSTED_GATE_APP_PRIVATE_KEY") != 1:
        raise ValueError("trusted-pr-auto.yml App private key may be referenced exactly once")
    if semantic.count('"statuses":"write"') != 1 or semantic.count("statuses: write") != 0:
        raise ValueError("trusted-pr-auto.yml native token must remain status-write-free")
    preflight = semantic.index("      - name: Qualify exact successful CI subject")
    deny = semantic.index("      - name: Stop automatic admission for protected changes")
    mint = semantic.index("      - name: Mint dedicated Trusted PR Gate token")
    report = semantic.index("      - name: Publish exact-subject Trusted PR Gate")
    if not preflight < deny < mint < report:
        raise ValueError("trusted admission, deny, token mint, and status publication are out of order")
    return {
        "trigger": "successful-reviewed-ci-workflow-run",
        "trusted_code_source": "default-branch-only",
        "protected_transition": "automatic-deny",
        "trusted_status_authority": "dedicated-app-token-after-exact-subject-preflight",
        "native_token": "read-only",
        "workflow_definition": "exact-reviewed-git-blob",
    }
