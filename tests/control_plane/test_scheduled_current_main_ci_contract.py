"""Exact-current-main CI recovery must execute full gates, not bot-owned cron."""

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
    assert "Bind native scheduled CI" not in text
    assert contract._trusted_auto._base._workflow_structure_sha1(text) == (
        contract.EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA
    )
    assert "schedule" not in contract._verify_ordinary_ci_workflow(text)["triggers"]


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
