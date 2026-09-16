from pathlib import Path


def replace_one(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8", newline="\n")


replace_one(
    ".github/scripts/dependency_promotion.py",
    '    api.post("/actions/workflows/ci.yml/dispatches", {"ref": branch, "inputs": {"subject_sha": head_sha}})',
    '    api.post("/actions/workflows/ci.yml/dispatches", {"ref": branch})',
)
replace_one(
    ".github/scripts/security_autoheal.py",
    '    api.post(\n        "/actions/workflows/ci.yml/dispatches",\n        {"ref": branch, "inputs": {"subject_sha": head_sha}},\n    )',
    '    api.post("/actions/workflows/ci.yml/dispatches", {"ref": branch})',
)
replace_one(
    "scripts/verify_ci_contract.py",
    '    "3d0055ce94ba7aeb9a2a0101c69506054978bb2d"  # pragma: allowlist secret',
    '    "4a426cdf3d0e623009d146d6350af1a75a6be8b3"  # pragma: allowlist secret',
)
replace_one(
    "scripts/verify_ci_contract.py",
    '''            "  merge_group:",\n            "  workflow_dispatch:",\n            "    inputs:",\n            "      subject_sha:",\n            "        description: Exact repository commit SHA to validate",\n            "        required: true",\n            "        type: string",''',
    '''            "  merge_group:",\n            "  workflow_dispatch:",''',
)
replace_one(
    "scripts/verify_ci_contract.py",
    '            "  CI_SUBJECT_SHA: ${{ github.event_name == \'workflow_dispatch\' && inputs.subject_sha || github.sha }}",',
    '            "  CI_SUBJECT_SHA: ${{ github.sha }}",',
)
replace_one(
    "scripts/verify_ci_contract.py",
    '        "subject": "github.sha-or-exact-workflow-dispatch-input",',
    '        "subject": "github.sha",',
)
replace_one(
    "scripts/verify_ci_contract.py",
    '        raise ValueError("ci.yml: trigger set must be exactly pull_request/push/merge_group")',
    '        raise ValueError("ci.yml: trigger set must be exactly pull_request/push/merge_group/workflow_dispatch")',
)
