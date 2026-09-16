#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

CI_BLOB = "3d0055ce94ba7aeb9a2a0101c69506054978bb2d"
DEPENDENCY_GOVERNANCE_BLOB = "9d09d68fe802e6e1c7a94933c14f7f9005e9a2a4"
SECURITY_AUTOHEAL_BLOB = "158a4d0444eb46ddbd438aa2c7466a8b0dddc26f"


def replace_one(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one replacement, found {count}: {old[:100]!r}")
    path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


def replace_between(path: Path, start: str, end: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8")
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{path}: start marker missing: {start[:100]!r}")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{path}: end marker missing: {end[:100]!r}")
    path.write_text(
        text[:start_index] + replacement + text[end_index:],
        encoding="utf-8",
        newline="\n",
    )


def harden_security_autoheal() -> None:
    path = Path(".github/scripts/security_autoheal.py")
    replace_one(path, "import re\nimport urllib.error", "import re\nimport tempfile\nimport urllib.error")

    text = path.read_text(encoding="utf-8")
    anchor = "SAFE_VERIFIER_LABELS = {\n"
    start = text.index(anchor)
    end = text.index("\n}\n", start) + len("\n}\n")
    mapping = r'''
DETERMINISTIC_LOG_REPAIRS = {
    "scripts/auto_trusted_report.py": (
        '    print(json.dumps(result, indent=2, sort_keys=True))',
        '    print(json.dumps({"result": result["result"], "reporter": "trusted-pr-gate"}, sort_keys=True))',
    ),
    "scripts/ci_contract_base.py": (
        '    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))',
        '    verify_ci_contract(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "ci-contract-base"}, sort_keys=True))',
    ),
    "scripts/verify_ci_contract.py": (
        '    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))',
        '    verify_ci_contract(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "ci-contract"}, sort_keys=True))',
    ),
    "scripts/verify_docs.py": (
        '    print(json.dumps(verify_documentation(root), indent=2, sort_keys=True))',
        '    verify_documentation(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "documentation-integrity"}, sort_keys=True))',
    ),
    "scripts/verify_fork_cloud_authority.py": (
        '    print(json.dumps(verify_repository(args.root), sort_keys=True, separators=(",", ":")))',
        '    verify_repository(args.root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "fork-cloud-authority"}, separators=(",", ":"), sort_keys=True))',
    ),
}
'''
    if "DETERMINISTIC_LOG_REPAIRS =" not in text:
        text = text[:end] + mapping + text[end:]
        path.write_text(text, encoding="utf-8", newline="\n")

    replace_between(
        path,
        '    if (\n        subject["rule"] == "py/clear-text-logging-sensitive-data"',
        '\n\n    return None\n',
        '''    if (\n        subject["rule"] == "py/clear-text-logging-sensitive-data"\n        and subject["path"] in DETERMINISTIC_LOG_REPAIRS\n    ):\n        old, new = DETERMINISTIC_LOG_REPAIRS[subject["path"]]\n        if text.count(old) != 1:\n            return None\n        return text.replace(old, new, 1)\n''',
    )

    replace_between(
        path,
        "def _generated_repairs(pulls: list[dict[str, Any]]) -> list[dict[str, Any]]:\n",
        "\n\ndef _attempt_count(api: GitHubApi, alert_number: int) -> int:\n",
        '''def _generated_repairs(pulls: list[dict[str, Any]]) -> list[dict[str, Any]]:\n    return [\n        pr\n        for pr in pulls\n        if (pr.get("user") or {}).get("login") == GITHUB_ACTIONS_LOGIN\n        and (pr.get("user") or {}).get("id") == GITHUB_ACTIONS_USER_ID\n        and isinstance(((pr.get("head") or {}).get("ref")), str)\n        and str((pr.get("head") or {}).get("ref")).startswith(BRANCH_PREFIX)\n        and _parse_marker(pr.get("body")) is not None\n    ]\n''',
    )

    replace_between(
        path,
        "def _attempt_count(api: GitHubApi, alert_number: int) -> int:\n",
        "\n\ndef _create_repair(\n",
        '''def _attempt_count(api: GitHubApi, alert_number: int) -> int:\n    rows = api.list_all("/pulls?state=closed&sort=updated&direction=desc", max_pages=2)\n    count = 0\n    for pr in rows:\n        if (pr.get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN:\n            continue\n        if (pr.get("user") or {}).get("id") != GITHUB_ACTIONS_USER_ID:\n            continue\n        branch = str((pr.get("head") or {}).get("ref") or "")\n        if not branch.startswith(BRANCH_PREFIX):\n            continue\n        metadata = _parse_marker(pr.get("body"))\n        if metadata is not None and metadata.get("alert") == alert_number:\n            count += 1\n    return count\n''',
    )

    replace_between(
        path,
        "def _merge(api: GitHubApi, pr_number: int, live: dict[str, Any], config: dict[str, Any]) -> None:\n",
        "\n\ndef _open_pulls(api: GitHubApi) -> list[dict[str, Any]]:\n",
        '''def _merge(\n    api: GitHubApi,\n    pr_number: int,\n    metadata: dict[str, Any],\n    live: dict[str, Any],\n    config: dict[str, Any],\n) -> None:\n    fresh = api.get(f"/pulls/{pr_number}")\n    rebound_metadata, rebound_live = _validate_generated_pr(api, fresh, config)\n    if rebound_metadata != metadata or rebound_live != live:\n        raise PolicyBlock("repair PR changed before guarded merge")\n    _require_green_checks(api, live["headSha"], config)\n    _verify_codeql_remediation(api, metadata, config)\n    result = api.put(\n        f"/pulls/{pr_number}/merge",\n        {"sha": live["headSha"], "merge_method": config["mergeMethod"]},\n    )\n    if not isinstance(result, dict) or result.get("merged") is not True:\n        message = result.get("message") if isinstance(result, dict) else result\n        raise AutohealError(f"GitHub declined security auto-heal merge: {message}")\n''',
    )
    replace_one(
        path,
        "                _merge(api, number, live, config)",
        "                _merge(api, number, validated_metadata, live, config)",
    )

    replace_between(
        path,
        "def selftest(config: dict[str, Any]) -> None:\n",
        "\n\ndef main() -> None:\n",
        r'''def selftest(config: dict[str, Any]) -> None:
    errors = validate_config(config)
    if errors:
        raise AutohealError("security auto-heal config self-test failed: " + "; ".join(errors))

    marker = _marker(
        {
            "version": 1,
            "alert": 7,
            "base": "a" * 40,
            "head": "b" * 40,
            "fingerprint": "c" * 64,
        }
    )
    parsed = _parse_marker(marker)
    if parsed is None or parsed.get("alert") != 7:
        raise AutohealError("auto-heal marker round-trip failed")

    original_root = globals()["ROOT"]
    try:
        with tempfile.TemporaryDirectory(prefix="security-autoheal-selftest-") as temporary:
            root = Path(temporary)
            globals()["ROOT"] = root

            permission_path = root / "tests" / "example.py"
            permission_path.parent.mkdir(parents=True)
            permission_path.write_text(
                "def wrapped_open(path: object, flags: int, mode: int = 0o777) -> int:\n"
                "    return 1\n",
                encoding="utf-8",
            )
            permission = _deterministic_repair(
                {
                    "rule": "py/overly-permissive-file",
                    "path": "tests/example.py",
                    "line": 1,
                }
            )
            if permission is None or "0o600" not in permission or "0o777" in permission:
                raise AutohealError("permission repair recipe self-test failed")

            for relative, (old, new) in DETERMINISTIC_LOG_REPAIRS.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(old + "\n", encoding="utf-8")
                repaired = _deterministic_repair(
                    {
                        "rule": "py/clear-text-logging-sensitive-data",
                        "path": relative,
                        "line": 1,
                    }
                )
                if repaired is None or old in repaired or new not in repaired:
                    raise AutohealError(f"logging repair recipe self-test failed: {relative}")
    finally:
        globals()["ROOT"] = original_root

    if _model_path_allowed(".github/workflows/ci.yml", config):
        raise AutohealError("model autofix authority expanded into .github")
    if not _model_path_allowed("tests/unit/test_example.py", config):
        raise AutohealError("model autofix authority unexpectedly excludes tests")
    if not _is_deterministic_only("scripts/verify_ci_contract.py", config):
        raise AutohealError("CI verifier must remain deterministic-only repair authority")
    spoofed = {
        "user": {"login": "attacker", "id": 1},
        "head": {"ref": BRANCH_PREFIX + "7-deadbeef"},
        "body": marker,
    }
    if _generated_repairs([spoofed]):
        raise AutohealError("non-Actions PR spoofed the generated-repair namespace")
    print("security-autoheal self-test: ok")
''',
    )


def patch_ci_contract() -> None:
    path = Path("scripts/verify_ci_contract.py")
    replace_one(
        path,
        '    "release-candidate.yml",\n    "trusted-pr-auto.yml",',
        '    "release-candidate.yml",\n    "security-autoheal.yml",\n    "trusted-pr-auto.yml",',
    )
    replace_one(
        path,
        'EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (\n    "66c0bf8aee2633bfb51c83029b0251f2d81dae29"  # pragma: allowlist secret\n)',
        f'EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA = (\n    "{CI_BLOB}"  # pragma: allowlist secret\n)',
    )
    replace_one(
        path,
        'EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA = (\n    "481821de8f4ae59430b1a9c28aae0d07a58e7201"  # pragma: allowlist secret\n)',
        f'EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA = (\n    "{DEPENDENCY_GOVERNANCE_BLOB}"  # pragma: allowlist secret\n)\nEXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA = (\n    "{SECURITY_AUTOHEAL_BLOB}"  # pragma: allowlist secret\n)',
    )

    replace_one(
        path,
        '''            "  merge_group:",\n        )''',
        '''            "  merge_group:",\n            "  workflow_dispatch:",\n            "    inputs:",\n            "      subject_sha:",\n            "        description: Exact repository commit SHA to validate",\n            "        required: true",\n            "        type: string",\n        )''',
    )
    replace_one(
        path,
        '''        "pull_request",\n        "push",\n        "merge_group",\n    }:''',
        '''        "pull_request",\n        "push",\n        "merge_group",\n        "workflow_dispatch",\n    }:''',
    )
    replace_one(
        path,
        '            "  CI_SUBJECT_SHA: ${{ github.sha }}",',
        '            "  CI_SUBJECT_SHA: ${{ github.event_name == \'workflow_dispatch\' && inputs.subject_sha || github.sha }}",',
    )
    replace_one(
        path,
        '        "repository_dispatch:",\n        "workflow_dispatch:",\n        "pull_request_target:",',
        '        "repository_dispatch:",\n        "pull_request_target:",',
    )
    replace_one(
        path,
        '        "triggers": ["merge_group", "pull_request", "push"],\n        "subject": "github.sha",',
        '        "triggers": ["merge_group", "pull_request", "push", "workflow_dispatch"],\n        "subject": "github.sha-or-exact-workflow-dispatch-input",',
    )

    dep_start = "def _verify_dependency_governance_workflow(text: str) -> dict[str, Any]:\n"
    dep_end = "\n\ndef _verify_release_candidate_workflow(text: str) -> dict[str, Any]:\n"
    dep_replacement = '''def _verify_dependency_governance_workflow(text: str) -> dict[str, Any]:\n    base = _trusted_auto._base\n    semantic = base._semantic_text(text)\n    if "  pull_request_target:" in semantic:\n        raise ValueError("dependency-governance.yml must not use pull_request_target")\n    if base._git_blob_sha1(text) != EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA:\n        raise ValueError(\n            "dependency-governance.yml bytes differ from the exact reviewed dependency authority"\n        )\n    required = (\n        "name: dependency-governance",\n        "  pull_request:",\n        "  workflow_run:",\n        "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL]",\n        "  schedule:",\n        "  workflow_dispatch:",\n        "permissions:\\n  contents: read",\n        "    name: governance-self-test",\n        "    name: govern-dependabot",\n        "    environment:\\n      name: trusted-pr-gate\\n      deployment: false",\n        "      actions: write",\n        "      checks: read",\n        "      contents: write",\n        "      pull-requests: write",\n        "      statuses: read",\n        "          ref: ${{ github.event.repository.default_branch }}",\n        "          persist-credentials: false",\n        "      - name: Set up Python 3.11",\n        "          python-version: '3.11.16'",\n        "      - name: Capture Python 3.11 resolver",\n        "          PROMOTION_PYTHON311=%s",\n        "      - name: Set up Python 3.14",\n        "          python-version: '3.14.7'",\n        "      - name: Capture Python 3.14 resolver",\n        "          PROMOTION_PYTHON314=%s",\n        "      - name: Attempt one bounded transient recovery",\n        "        run: python .github/scripts/dependency_recovery.py --recover",\n        "      - name: Mint dedicated Trusted PR Gate token",\n        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",\n        '\"permissions\":{\"contents\":\"read\",\"pull_requests\":\"read\",\"statuses\":\"write\"}',\n        "      - name: Reconcile exact-subject Python dependency promotion",\n        "        run: python .github/scripts/dependency_promotion.py --reconcile --allow-merge",\n        "      - name: Reconcile Dependabot action merge authority",\n        '          python .github/scripts/dependency_governance.py "${args[@]}"',\n    )\n    for fragment in required:\n        if fragment not in semantic:\n            raise ValueError(\n                f"dependency-governance.yml missing reviewed authority invariant: {fragment}"\n            )\n    for forbidden in (\n        "repository_dispatch:",\n        "ubuntu-latest",\n        "continue-on-error: true",\n        "ref: ${{ github.event.pull_request.head.sha }}",\n        "ref: ${{ github.event.workflow_run.head_sha }}",\n    ):\n        if forbidden in semantic:\n            raise ValueError(\n                f"dependency-governance.yml contains forbidden authority token: {forbidden}"\n            )\n    if semantic.count('\"statuses\":\"write\"') != 1 or semantic.count("statuses: write") != 0:\n        raise ValueError("native workflow authority must remain status-read-only")\n    recovery = semantic.index("      - name: Attempt one bounded transient recovery")\n    mint = semantic.index("      - name: Mint dedicated Trusted PR Gate token")\n    promotion = semantic.index("      - name: Reconcile exact-subject Python dependency promotion")\n    actions = semantic.index("      - name: Reconcile Dependabot action merge authority")\n    if not recovery < mint < promotion < actions:\n        raise ValueError(\n            "dependency recovery, trusted-token minting, Python promotion, and action reconciliation are out of order"\n        )\n    return {\n        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],\n        "trusted_code_source": "default-branch-only-for-authority-job",\n        "recovery_authority": "one-rerun-no-branch-mutation-no-merge",\n        "python_merge_authority": "signed-dependabot-source-plus-deterministic-lock-promotion",\n        "action_merge_authority": "single-provenance-qualified-dependabot-controller",\n        "trusted_status_authority": "dedicated-app-token-after-exact-subject-proof",\n        "workflow_definition": "exact-reviewed-git-blob",\n    }\n'''
    replace_between(path, dep_start, dep_end, dep_replacement)

    security_fn = '''\n\ndef _verify_security_autoheal_workflow(text: str) -> dict[str, Any]:\n    base = _trusted_auto._base\n    semantic = base._semantic_text(text)\n    if base._git_blob_sha1(text) != EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA:\n        raise ValueError("security-autoheal.yml bytes differ from the exact reviewed security authority")\n    required = (\n        "name: Security Auto-Heal",\n        "  pull_request:",\n        "  workflow_run:",\n        "      - CodeQL",\n        "      - 'CI — ƳƤ AI QA Automation Framework'",\n        "  schedule:",\n        "  workflow_dispatch:",\n        "permissions:\\n  contents: read",\n        "    name: security-autoheal-self-test",\n        "    name: reconcile-codeql-autoheal",\n        "    environment:\\n      name: trusted-pr-gate\\n      deployment: false",\n        "      actions: write",\n        "      checks: read",\n        "      contents: write",\n        "      pull-requests: write",\n        "      security-events: write",\n        "      statuses: read",\n        "          ref: ${{ github.event.repository.default_branch }}",\n        "          persist-credentials: false",\n        "      - name: Mint dedicated Trusted PR Gate token",\n        "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",\n        '\"permissions\":{\"contents\":\"read\",\"pull_requests\":\"read\",\"statuses\":\"write\"}',\n        "      - name: Reconcile exact-subject CodeQL remediations",\n        "          GITHUB_TOKEN: ${{ github.token }}",\n        "          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",\n        "        run: python .github/scripts/security_autoheal.py --reconcile --allow-merge",\n    )\n    for fragment in required:\n        if fragment not in semantic:\n            raise ValueError(f"security-autoheal.yml missing reviewed authority invariant: {fragment}")\n    for forbidden in (\n        "pull_request_target:",\n        "repository_dispatch:",\n        "ubuntu-latest",\n        "continue-on-error: true",\n        "id-token: write",\n    ):\n        if forbidden in semantic:\n            raise ValueError(f"security-autoheal.yml contains forbidden authority token: {forbidden}")\n    if semantic.count('\"statuses\":\"write\"') != 1 or semantic.count("statuses: write") != 0:\n        raise ValueError("security auto-heal native workflow authority must remain status-read-only")\n    return {\n        "triggers": ["pull_request", "workflow_run", "schedule", "workflow_dispatch"],\n        "trusted_code_source": "default-branch-only-for-authority-job",\n        "repair_authority": "code-owned-rule-and-path-bounded-generated-prs",\n        "merge_authority": "security-autoheal-namespace-only-after-exact-subject-proof",\n        "trusted_status_authority": "dedicated-app-token-after-codeql-remediation-proof",\n        "workflow_definition": "exact-reviewed-git-blob",\n    }\n'''
    marker = "\n\ndef _verify_release_candidate_workflow(text: str) -> dict[str, Any]:\n"
    text = path.read_text(encoding="utf-8")
    if "def _verify_security_autoheal_workflow" not in text:
        if marker not in text:
            raise SystemExit("verify_ci_contract: release-candidate marker missing")
        path.write_text(text.replace(marker, security_fn + marker, 1), encoding="utf-8", newline="\n")

    replace_one(
        path,
        '    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])\n    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(workflows["trusted-pr-auto.yml"])',
        '    release_candidate = _verify_release_candidate_workflow(workflows["release-candidate.yml"])\n    security_autoheal = _verify_security_autoheal_workflow(workflows["security-autoheal.yml"])\n    trusted_auto = _trusted_auto._verify_trusted_auto_workflow(workflows["trusted-pr-auto.yml"])',
    )
    replace_one(
        path,
        '            "release_candidate": release_candidate,\n            "trusted_auto": trusted_auto,',
        '            "release_candidate": release_candidate,\n            "security_autoheal": security_autoheal,\n            "trusted_auto": trusted_auto,',
    )


def patch_fork_authority() -> None:
    path = Path("scripts/verify_fork_cloud_authority.py")
    replace_one(
        path,
        '    "release-candidate.yml",\n    "trusted-pr-auto.yml",',
        '    "release-candidate.yml",\n    "security-autoheal.yml",\n    "trusted-pr-auto.yml",',
    )
    replace_one(
        path,
        '    "manual-validation.yml": Counter({"ANTHROPIC_API_KEY": 2}),\n    "trusted-pr-auto.yml": Counter({"TRUSTED_GATE_APP_PRIVATE_KEY": 1}),',
        '    "manual-validation.yml": Counter({"ANTHROPIC_API_KEY": 2}),\n    "security-autoheal.yml": Counter({"TRUSTED_GATE_APP_PRIVATE_KEY": 1}),\n    "trusted-pr-auto.yml": Counter({"TRUSTED_GATE_APP_PRIVATE_KEY": 1}),',
    )
    text = path.read_text(encoding="utf-8")
    old_governance = '''_GOVERNANCE_SECRET_CONTEXT_FRAGMENTS = (\n    "- name: Attempt one bounded transient recovery\\n        if: github.event_name == 'workflow_run' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\\n        env:\\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",\n    "- name: Mint dedicated Trusted PR Gate token\\n        id: trusted-app\\n        if: github.event_name == 'workflow_run' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\\n        env:\\n          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}\\n          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",\n    "- name: Reconcile Dependabot merge authority\\n        env:\\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\\n          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",\n)\n'''
    new_governance = '''_GOVERNANCE_SECRET_CONTEXT_FRAGMENTS = (\n    "- name: Attempt one bounded transient recovery\\n        if: github.event_name == 'workflow_run' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\\n        env:\\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}",\n    "- name: Mint dedicated Trusted PR Gate token\\n        id: trusted-app\\n        if: github.event_name == 'workflow_run' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'\\n        env:\\n          TRUSTED_GATE_APP_CLIENT_ID: ${{ vars.TRUSTED_GATE_APP_CLIENT_ID }}\\n          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",\n    "- name: Reconcile exact-subject Python dependency promotion\\n        env:\\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\\n          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",\n    "- name: Reconcile Dependabot action merge authority\\n        env:\\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\\n          TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",\n)\n_SECURITY_AUTOHEAL_SECRET_CONTEXT_FRAGMENTS = (\n    "environment:\\n      name: trusted-pr-gate\\n      deployment: false",\n    "TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",\n    "GITHUB_TOKEN: ${{ github.token }}",\n    "TRUSTED_STATUS_TOKEN: ${{ steps.trusted-app.outputs.token }}",\n    "run: python .github/scripts/security_autoheal.py --reconcile --allow-merge",\n)\n'''
    if text.count(old_governance) != 1:
        raise SystemExit("fork authority: governance secret context block drifted")
    text = text.replace(old_governance, new_governance, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    replace_one(
        path,
        '''    if name == "dependency-governance.yml":\n        missing = [\n            fragment for fragment in _GOVERNANCE_SECRET_CONTEXT_FRAGMENTS if fragment not in text\n        ]\n        if missing:\n            raise ValueError(\n                "dependency-governance.yml: reviewed credential consumers moved or changed"\n            )\n''',
        '''    if name == "dependency-governance.yml":\n        missing = [\n            fragment for fragment in _GOVERNANCE_SECRET_CONTEXT_FRAGMENTS if fragment not in text\n        ]\n        if missing:\n            raise ValueError(\n                "dependency-governance.yml: reviewed credential consumers moved or changed"\n            )\n    if name == "security-autoheal.yml":\n        missing = [\n            fragment for fragment in _SECURITY_AUTOHEAL_SECRET_CONTEXT_FRAGMENTS if fragment not in text\n        ]\n        if missing:\n            raise ValueError(\n                "security-autoheal.yml: reviewed credential consumers moved or changed"\n            )\n''',
    )


if __name__ == "__main__":
    harden_security_autoheal()
    patch_ci_contract()
    patch_fork_authority()
