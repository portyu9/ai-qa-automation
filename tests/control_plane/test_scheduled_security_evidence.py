"""Native security retains strict scanners; owner-bound reusable recovery replaces bot cron."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
contract = importlib.import_module("verify_ci_contract")
SECURITY = ROOT / ".github" / "workflows" / "security.yml"


def test_native_security_keeps_scanners_and_fail_closed_terminal_gate() -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert "\n  schedule:\n" not in text
    assert "Bind native scheduled Security" not in text
    result = contract._verify_security_evidence_workflow(text)
    assert result["triggers"] == ["pull_request", "push", "workflow_dispatch"]
    assert result["terminal_check"] == "security-gate"


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ("  workflow_dispatch:", '  schedule:\n    - cron: "*/5 * * * *"\n  workflow_dispatch:'),
        ("    name: security-gate", "    name: Fake Gate"),
        ("bandit -c pyproject.toml -q -r src", "true"),
        ('test "$SECURITY_SCAN" = "success"', "true"),
    ],
)
def test_security_guard_mutation_fails_closed(needle: str, replacement: str) -> None:
    text = SECURITY.read_text(encoding="utf-8")
    assert needle in text
    with pytest.raises(ValueError):
        contract._verify_security_evidence_workflow(text.replace(needle, replacement, 1))
