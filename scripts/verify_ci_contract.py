from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

MAX_WORKFLOW_BYTES = 256 * 1024
EXPECTED_WORKFLOW_NAMES = {"ci.yml", "manual-validation.yml"}
EXPECTED_ACTION_SHAS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",  # pragma: allowlist secret
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",  # pragma: allowlist secret
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # pragma: allowlist secret
}
ACTION_RE = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WRITE_PERMISSION_RE = re.compile(r"^\s+[A-Za-z0-9_-]+:\s*write\s*$", re.MULTILINE)
AUTOMATIC_REQUIRED_JOBS = (
    "quality",
    "deterministic-evals",
    "supply-chain",
    "security",
    "browser-reference-sut",
)


def _read_regular_text(path: Path) -> str:
    if path.is_symlink():
        raise ValueError(f"workflow path must not be a symlink: {path}")
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"workflow path must be a regular file: {path}")
    if before.st_size > MAX_WORKFLOW_BYTES:
        raise ValueError(f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes: {path}")
    data = path.read_bytes()
    if len(data) > MAX_WORKFLOW_BYTES:
        raise ValueError(f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes during ingestion: {path}")
    after = path.stat(follow_symlinks=False)
    signature_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    signature_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    if signature_before != signature_after:
        raise ValueError(f"workflow changed during ingestion: {path}")
    text = data.decode("utf-8")
    if not text.strip():
        raise ValueError(f"workflow must not be empty: {path}")
    return text


def _verify_action_revisions(workflows: dict[str, str]) -> dict[str, str]:
    observed: dict[str, str] = {}
    for name, text in workflows.items():
        for action, revision in ACTION_RE.findall(text):
            if not HEX40_RE.fullmatch(revision):
                raise ValueError(f"{name}: mutable GitHub Action reference: {action}@{revision}")
            expected = EXPECTED_ACTION_SHAS.get(action)
            if expected is None:
                raise ValueError(f"{name}: unreviewed GitHub Action: {action}")
            if revision != expected:
                raise ValueError(f"{name}: unexpected immutable revision for {action}: {revision}")
            observed[action] = revision
    if set(observed) != set(EXPECTED_ACTION_SHAS):
        raise ValueError("workflow Action set differs from the reviewed immutable set")
    return observed


def _verify_read_only_permissions(text: str, *, name: str) -> None:
    if "permissions:\n  contents: read" not in text:
        raise ValueError(f"{name}: workflow must declare contents: read")
    if WRITE_PERMISSION_RE.search(text):
        raise ValueError(f"{name}: workflow requests write permission")


def _verify_checkout_binding(text: str, *, name: str) -> int:
    checkout = f"uses: actions/checkout@{EXPECTED_ACTION_SHAS['actions/checkout']}"
    checkout_count = text.count(checkout)
    if checkout_count < 1:
        raise ValueError(f"{name}: workflow must checkout a source subject")
    if text.count("ref: ${{ github.sha }}") != checkout_count:
        raise ValueError(f"{name}: every checkout must bind to github.sha")
    if text.count("persist-credentials: false") != checkout_count:
        raise ValueError(f"{name}: every checkout must disable persisted credentials")
    exact_check = 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"'
    if text.count(exact_check) != checkout_count:
        raise ValueError(f"{name}: every checkout must verify the exact GitHub event revision")
    return checkout_count


def _verify_automatic_workflow(text: str) -> dict[str, Any]:
    name = "ci.yml"
    for token in ("\n  pull_request:\n", "\n  push:\n", "\n  merge_group:\n"):
        if token not in text:
            raise ValueError(f"{name}: missing required automatic trigger {token.strip()}")
    for forbidden in (
        "workflow_dispatch:",
        "pull_request_target:",
        "${{ secrets.",
        "ANTHROPIC_API_KEY",
        "${{ inputs.",
        "continue-on-error: true",
    ):
        if forbidden in text:
            raise ValueError(f"{name}: forbidden automatic-CI authority token: {forbidden}")
    if "ubuntu-latest" in text:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if '"3.11.16"' not in text or '"3.13.15"' not in text:
        raise ValueError(f"{name}: exact supported Python patch versions are required")
    if "--require-hashes" not in text:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in text or " --editable" in text or " -e ." in text:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    if "cancel-in-progress: true" not in text:
        raise ValueError(f"{name}: stale PR executions must be cancelled on superseding revisions")
    _verify_read_only_permissions(text, name=name)
    checkout_count = _verify_checkout_binding(text, name=name)

    if "name: Required PR Gate" not in text or "if: ${{ always() }}" not in text:
        raise ValueError(f"{name}: stable fail-closed Required PR Gate is missing")
    for job in AUTOMATIC_REQUIRED_JOBS:
        if f"      - {job}\n" not in text:
            raise ValueError(f"{name}: Required PR Gate does not depend on {job}")
        if f'needs.{job}.result }}" = "success"' not in text:
            raise ValueError(f"{name}: Required PR Gate does not fail closed on {job}")

    return {
        "triggers": ["pull_request", "push", "merge_group"],
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "required_gate": "Required PR Gate",
        "permissions": "contents:read",
        "secrets": False,
    }


def _verify_manual_workflow(text: str) -> dict[str, Any]:
    name = "manual-validation.yml"
    if "\n  workflow_dispatch:\n" not in text:
        raise ValueError(f"{name}: workflow_dispatch is required")
    for forbidden in ("pull_request_target:", "\n  pull_request:\n", "\n  push:\n", "\n  merge_group:\n"):
        if forbidden in text:
            raise ValueError(f"{name}: automatic trigger is forbidden: {forbidden.strip()}")
    if "ubuntu-latest" in text:
        raise ValueError(f"{name}: moving ubuntu-latest runner label is forbidden")
    if "${{ inputs.run_holdout }}" not in text or "${{ inputs.run_model }}" not in text:
        raise ValueError(f"{name}: explicit holdout/model dispatch controls are required")
    if "${{ secrets.ANTHROPIC_API_KEY }}" not in text:
        raise ValueError(f"{name}: credentialed model job must use the explicit configured secret")
    if "--require-hashes" not in text:
        raise ValueError(f"{name}: hash-required dependency installation is required")
    if "pip install --upgrade" in text or " --editable" in text or " -e ." in text:
        raise ValueError(f"{name}: live/editable dependency installation is forbidden")
    _verify_read_only_permissions(text, name=name)
    checkout_count = _verify_checkout_binding(text, name=name)
    return {
        "trigger": "workflow_dispatch",
        "subject": "github.sha",
        "checkout_count": checkout_count,
        "permissions": "contents:read",
        "credentialed_model": "manual-only",
        "holdout": "manual-separated",
    }


def verify_ci_contract(root: Path) -> dict[str, Any]:
    root = root.resolve()
    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_symlink() or not workflow_dir.is_dir():
        raise ValueError("workflow directory must be a regular repository directory")
    observed_names = {
        entry.name
        for entry in workflow_dir.iterdir()
        if entry.suffix.lower() in {".yml", ".yaml"}
    }
    if observed_names != EXPECTED_WORKFLOW_NAMES:
        raise ValueError(
            f"unexpected workflow set: expected {sorted(EXPECTED_WORKFLOW_NAMES)}, "
            f"got {sorted(observed_names)}"
        )

    workflows = {name: _read_regular_text(workflow_dir / name) for name in sorted(observed_names)}
    actions = _verify_action_revisions(workflows)
    automatic = _verify_automatic_workflow(workflows["ci.yml"])
    manual = _verify_manual_workflow(workflows["manual-validation.yml"])
    return {
        "schema_version": 1,
        "result": "PASS",
        "claim": "repository workflow definitions satisfy deterministic CI authority invariants",
        "workflows": {
            "automatic": automatic,
            "manual": manual,
        },
        "actions": actions,
        "limitations": [
            "Repository workflow validation does not prove GitHub branch protection or required-check settings are enabled.",
            "A green pull_request run validates GitHub's event SHA, which is normally the prospective merge subject rather than the PR head commit alone.",
            "Credential existence, environment protection, hosted-runner identity, and external service availability remain environment-owned facts.",
        ],
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
