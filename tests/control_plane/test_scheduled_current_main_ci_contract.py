"""Native CI full gates must run after authenticated successful scheduled main sentinel."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
contract = importlib.import_module("verify_ci_contract")
CI = ROOT / ".github" / "workflows" / "ci.yml"
WAKE = ROOT / ".github" / "workflows" / "current-main-ci-wake.yml"


def test_native_ci_keeps_all_pr_and_push_gates_without_bot_cron() -> None:
    text = CI.read_text(encoding="utf-8")
    assert "\n  schedule:\n" not in text
    assert "Authenticate genuine scheduled sentinel and current main for native CI" in text
    assert contract._trusted_auto._base._workflow_structure_sha1(text) == (
        contract.EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA
    )
    triggers = contract.verify_ci_contract(ROOT)["workflows"]["automatic"]["triggers"]
    assert "schedule" not in triggers
    assert "workflow_run" in triggers


def test_recovery_calls_full_exact_subject_ci_and_codeql() -> None:
    text = WAKE.read_text(encoding="utf-8")
    assert "/dispatches" not in text
    assert contract._verify_current_main_ci_wake_workflow(text)["authority"] == (
        "exact-current-main-reusable-ci-and-codeql-only"
    )


@pytest.mark.parametrize(
    ("path", "needle", "replacement"),
    [
        (CI, "  merge_group:", '  schedule:\n    - cron: "*/5 * * * *"\n  merge_group:'),
        (CI, "    name: Required PR Gate", "    name: Fake Pass"),
        (WAKE, "    uses: ./.github/workflows/reusable-ci.yml", "    uses: ./untrusted.yml"),
        (WAKE, "    name: Exact Current-Main Recovery Gate", "    name: Fake Recovery"),
        (WAKE, "($now - 86400)", "($now - 31536000)"),
        (WAKE, "run_validation=true", "run_validation=false"),
    ],
)
def test_mutated_source_fails_closed(path: Path, needle: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    assert needle in source
    changed = source.replace(needle, replacement, 1)
    with pytest.raises(ValueError):
        if path == CI:
            contract._verify_ordinary_ci_workflow(changed)
        else:
            contract._verify_current_main_ci_wake_workflow(changed)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (".run_attempt == 1 and", ".run_attempt >= 1 and"),
        ("        if: github.event_name == 'workflow_run'", "        if: always()"),
        (".head_sha == $sha and", ".head_sha != $sha and"),
        (
            '.path == ".github/workflows/ruleset-drift-sentinel.yml" and',
            '.path != ".github/workflows/ruleset-drift-sentinel.yml" and',
        ),
        (
            "       github.event.workflow_run.head_sha == github.sha)",
            "       github.event.workflow_run.head_sha != github.sha)",
        ),
    ],
)
def test_native_scheduled_ci_provenance_mutations_are_rejected(
    needle: str, replacement: str
) -> None:
    text = CI.read_text(encoding="utf-8")
    assert text.count(needle) == 1
    with pytest.raises(ValueError):
        contract._verify_ordinary_ci_workflow(text.replace(needle, replacement, 1))
