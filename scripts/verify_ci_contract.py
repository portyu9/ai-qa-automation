from __future__ import annotations

import importlib.util
import json
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

# Preserve the complete hardened verifier API because the existing adversarial tests import
# its private helpers directly. This wrapper adds independently frozen workflow contracts
# without weakening any pre-existing invariant.
for _export_name in dir(_base):
    if not _export_name.startswith("__"):
        globals()[_export_name] = getattr(_base, _export_name)
del _export_name

EXPECTED_WORKFLOW_NAMES = {
    "ci.yml",
    "manual-validation.yml",
    "python314-lock-candidate.yml",
    "trusted-pr-auto.yml",
}
EXPECTED_TRUSTED_AUTO_WORKFLOW_BLOB_SHA = (
    "44f15cfa9b844307d539d0e2c84405e1f74d56ee"  # pragma: allowlist secret
)
EXPECTED_LOCK_CANDIDATE_WORKFLOW_BLOB_SHA = (
    "4597abb3c61b6369291d81a778494ecd65bde42b"  # pragma: allowlist secret
)
EXPECTED_BASE_VERIFIER_BLOB_SHA = (
    "c7aec0364b4c1c53220abe6a06674e59430707cb"  # pragma: allowlist secret
)
TRUSTED_AUTO_WORKFLOW_NAME = "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework"
TRUSTED_AUTO_SOURCE_WORKFLOW = "CI — ƳƤ AI QA Automation Framework"
TRUSTED_AUTO_PROTECTED_PATHS = (
    ".github",
    ".claude",
    ".dockerignore",
    ".mcp.json",
    ".pre-commit-config.yaml",
    "CLAUDE.md",
    "Dockerfile",
    "evals",
    "examples",
    "pyproject.toml",
    "requirements",
    "scripts",
    "tests",
    "src/ai_qa_automation/__init__.py",
    "src/ai_qa_automation/io_safety.py",
    "src/ai_qa_automation/tools/__init__.py",
    "src/ai_qa_automation/tools/execution_env.py",
)

# The base verifier must accept the additional independently frozen workflow definitions
# before it performs its existing exact workflow-set and immutable-action checks. No other
# base invariant is changed.
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
        raise ValueError(
            "trusted-pr-auto.yml native GitHub token must never request write authority"
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

    preflight = _base._semantic_text(_base._job_block(text, "preflight"))
    required_preflight = (
        "    name: Automatic Trusted Admission",
        "    if: ${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success' }}",
        "          ref: ${{ github.sha }}",
        "          persist-credentials: false",
        '        run: test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python scripts/auto_trusted_preflight.py \\",
        '            --event "$GITHUB_EVENT_PATH" \\',
        '            --github-output "$GITHUB_OUTPUT"',
        '          test "$TRUSTED_SHA" = "$GITHUB_SHA"',
        '            test "$PROTECTED_CHANGES_JSON" = "[]"',
    )
    for fragment in required_preflight:
        if fragment not in preflight:
            raise ValueError(
                f"trusted automatic preflight is missing reviewed fragment: {fragment}"
            )
    if "needs.preflight.outputs.merge_sha" in preflight:
        raise ValueError("trusted automatic preflight must not checkout or execute candidate bytes")

    subject_guard = _base._semantic_text(_base._job_block(text, "subject-guard"))
    required_guard = (
        "    name: Exact Subject + Protected Authority Guard",
        "    needs: preflight",
        "    if: ${{ needs.preflight.result == 'success' && needs.preflight.outputs.eligible == 'true' }}",
        "          ref: ${{ needs.preflight.outputs.merge_sha }}",
        "          persist-credentials: false",
        '          test "$EXPECTED_BASE_SHA" = "$EXPECTED_TRUSTED_SHA"',
        '          test "$(git rev-parse HEAD)" = "$EXPECTED_MERGE_SHA"',
        '          read -r merge_sha base_sha head_sha extra_parent < <("${git_clean_env[@]}" /usr/bin/git rev-list --parents -n 1 "$EXPECTED_MERGE_SHA")',
        '            base_oid="$(oid_for "$EXPECTED_BASE_SHA" "$path")"',
        '            subject_oid="$(oid_for "$EXPECTED_MERGE_SHA" "$path")"',
        '            test "$base_oid" = "$subject_oid"',
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
    if semantic.count(trusted_checkout) != 1:
        raise ValueError("trusted automatic reporter must have exactly one trusted-base checkout")
    if semantic.count("persist-credentials: false") != 8:
        raise ValueError("every trusted automatic checkout must disable persisted credentials")

    validation_jobs = (
        "supply-chain",
        "quality",
        "deterministic-evals",
        "security",
        "browser-reference-sut",
    )
    for job_id in validation_jobs:
        job = _base._semantic_text(_base._job_block(text, job_id))
        if candidate_checkout not in job:
            raise ValueError(
                f"trusted automatic validation job {job_id} is not merge-subject-bound"
            )
        if "${{ secrets." in job:
            raise ValueError(f"trusted automatic validation job {job_id} must be secret-free")
        if "persist-credentials: false" not in job:
            raise ValueError(f"trusted automatic validation job {job_id} must disable credentials")

    supply_chain = _base._semantic_text(_base._job_block(text, "supply-chain"))
    mermaid_subject_binding = (
        "      - name: Render Mermaid documentation with digest-pinned official CLI\n"
        "        env:\n"
        "          CI_SUBJECT_SHA: ${{ needs.preflight.outputs.merge_sha }}\n"
        "        run: |"
    )
    if mermaid_subject_binding not in supply_chain:
        raise ValueError(
            "trusted Mermaid validation must bind CI_SUBJECT_SHA to the exact prospective merge"
        )

    required_gate = _base._semantic_text(_base._job_block(text, "required-gate"))
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

    reporter = _base._semantic_text(_base._job_block(text, "trusted-status"))
    required_reporter = (
        "    name: Automatic Trusted PR Gate Reporter",
        "    environment:\n      name: trusted-pr-gate\n      deployment: false",
        "    permissions:\n      actions: read\n      contents: read\n      pull-requests: read",
        trusted_checkout,
        "      - name: Revalidate automatic trusted admission",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          python scripts/auto_trusted_preflight.py \\",
        "      - name: Require exact final admission identity",
        '          test "$FINAL_ELIGIBLE" = "true"',
        '          test "$FINAL_PROTECTED_CHANGES" = "[]"',
        '          test "$FINAL_MERGE_SHA" = "$EXPECTED_MERGE_SHA"',
        '          test "$FINAL_TRUSTED_SHA" = "$GITHUB_SHA"',
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
    if semantic.count("${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}") != 1:
        raise ValueError("automatic trusted App private key must have exactly one consumer")
    if semantic.count("${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}") != 1:
        raise ValueError("automatic trusted App client ID must have exactly one consumer")
    if "${{ secrets." in semantic.replace(reporter, ""):
        raise ValueError("automatic trusted environment secrets must be isolated to reporter")

    revalidate_position = reporter.index("      - name: Revalidate automatic trusted admission")
    final_identity_position = reporter.index("      - name: Require exact final admission identity")
    mint_position = reporter.index("      - name: Mint dedicated Trusted PR Gate token")
    publish_position = reporter.index(
        "      - name: Publish automatic exact-subject trusted status"
    )
    if not revalidate_position < final_identity_position < mint_position < publish_position:
        raise ValueError("automatic trusted reporter authority steps are out of reviewed order")

    return {
        "trigger": "workflow_run:completed:reviewed-ci",
        "wake_signal": "successful-owner-same-repository-pull-request-ci",
        "trusted_definition": "default-branch-workflow-run-revision",
        "candidate_execution_guard": "exact-merge-parents-plus-zero-protected-object-drift",
        "protected_paths": list(TRUSTED_AUTO_PROTECTED_PATHS),
        "validation_subject": "live-prospective-merge-sha",
        "validation_authority": "read-only-secret-free-before-reporter",
        "terminal_revalidation": "fresh-live-admission-plus-shared-pr-head-base-merge-resolver",
        "status_writer": "dedicated-github-app",
        "maintenance_fallback": "owner-repository-dispatch-exact-object-manifest",
        "workflow_definition": "exact-reviewed-git-blob",
    }


def _verify_lock_candidate_workflow(text: str) -> dict[str, Any]:
    semantic = _base._semantic_text(text)
    if _base._git_blob_sha1(text) != EXPECTED_LOCK_CANDIDATE_WORKFLOW_BLOB_SHA:
        raise ValueError(
            "python314-lock-candidate.yml bytes differ from the exact reviewed temporary definition"
        )

    on_block = _base._semantic_text(_base._top_level_block(text, "on")).strip("\n")
    expected_on = "\n".join(
        (
            "on:",
            "  pull_request:",
            "    branches: [main]",
            "    types: [opened, synchronize, reopened]",
        )
    )
    if on_block != expected_on:
        raise ValueError("Python 3.14 lock candidate workflow trigger differs from reviewed definition")
    permissions = _base._permissions(_base._top_level_block(text, "permissions"))
    if permissions != {"contents": "read"}:
        raise ValueError("Python 3.14 lock candidate workflow must be read-only")
    if _base.WRITE_PERMISSION_RE.search(semantic):
        raise ValueError("Python 3.14 lock candidate workflow must never request write authority")
    for forbidden in (
        "actions/checkout@",
        "${{ secrets.",
        "${{ github.token }}",
        "GITHUB_TOKEN",
        "pull_request_target:",
        "repository_dispatch:",
        "workflow_dispatch:",
        "continue-on-error: true",
        "ubuntu-latest",
        "cache:",
        "sudo ",
        "apt-get ",
        "apt install ",
        "git push",
    ):
        if forbidden in semantic:
            raise ValueError(
                f"Python 3.14 lock candidate workflow contains forbidden authority token: {forbidden}"
            )

    required = (
        "    if: github.head_ref == 'ci-python-314-certification'",
        "    runs-on: ubuntu-24.04",
        '          python-version: "3.14.7"',
        "          SOURCE_SHA: ${{ github.event.pull_request.head.sha }}",
        "https://raw.githubusercontent.com/{repository}/{source_sha}/pyproject.toml",
        "uv==0.12.1 --hash=sha256:27211df9b277f440dea438a4e525ba40250fb721ad39b8927eefc2d91f9aea15",
        "python -m pip install --no-deps --only-binary=:all: --require-hashes",
        "test \"$(uv --version)\" = 'uv 0.12.1'",
        "--python-version '3.14.7'",
        "--generate-hashes",
        "--no-header",
        "cmp -s generated/dev-py314-a.lock generated/dev-py314-b.lock",
        "test \"$(stat -c '%s' \"$lock\")\" -le 1048576",
        "'source_sha': source_sha",
        "'pyproject_sha256': hashlib.sha256(pyproject).hexdigest()",
        "'lock_sha256': hashlib.sha256(lock).hexdigest()",
        "      - name: Upload inert lock candidate evidence",
        "          name: python314-lock-candidate-${{ github.event.pull_request.head.sha }}",
        "            generated/dev-py314.lock",
        "            generated/lock-provenance.json",
        "          retention-days: 3",
    )
    for fragment in required:
        if fragment not in semantic:
            raise ValueError(
                f"Python 3.14 lock candidate workflow is missing reviewed fragment: {fragment}"
            )
    if semantic.count("actions/setup-python@") != 1:
        raise ValueError("Python 3.14 lock candidate must set up Python exactly once")
    if semantic.count("actions/upload-artifact@") != 1:
        raise ValueError("Python 3.14 lock candidate must upload evidence exactly once")
    if semantic.count("uv pip compile") != 2:
        raise ValueError("Python 3.14 lock candidate must independently resolve the lock twice")

    return {
        "purpose": "temporary-read-only-lock-candidate",
        "source": "exact-pr-head-pyproject",
        "python_version": "3.14.7",
        "uv_version": "0.12.1",
        "resolution": "double-compile-byte-identity",
        "mutation": "none",
        "workflow_definition": "exact-reviewed-git-blob",
    }


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    _verify_frozen_base()
    _base.EXPECTED_WORKFLOW_NAMES = EXPECTED_WORKFLOW_NAMES
    result = _base.verify_ci_contract(root)
    snapshots = _base._read_workflow_set(root / ".github" / "workflows")
    trusted_auto = _verify_trusted_auto_workflow(snapshots["trusted-pr-auto.yml"].text)
    lock_candidate = _verify_lock_candidate_workflow(snapshots["python314-lock-candidate.yml"].text)
    result["workflows"]["trusted_auto"] = trusted_auto
    result["workflows"]["python314_lock_candidate"] = lock_candidate
    result["limitations"].append(
        "Automatic trusted admission intentionally refuses any PR that changes a protected authority root; those maintenance changes still require the explicit owner repository_dispatch manifest path."
    )
    result["limitations"].append(
        "Repository source can verify the workflow_run design but cannot prove external Actions Policy permits workflow_run until a post-merge live proof run is observed."
    )
    result["limitations"].append(
        "The Python 3.14 lock-candidate workflow is temporary read-only generation evidence; its artifact is not merge authority and the workflow must be removed before certification closure."
    )
    return result


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
