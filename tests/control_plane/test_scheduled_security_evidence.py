"""Independent native security schedule is an exact-current-main bound event."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
contract = importlib.import_module("verify_ci_contract")
SECURITY = ROOT / ".github" / "workflows" / "security.yml"


def test_native_security_recovery_retains_full_scanners_and_trigger_authority() -> None:
    source = SECURITY.read_text(encoding="utf-8")
    detail = contract._verify_security_evidence_workflow(source)
    assert '    - cron: "47 11,14,23 * * *"' in source
    assert detail["terminal_check"] == "security-gate"


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('    - cron: "47 11,14,23 * * *"', '    - cron: "41 * * * *"'),
        (
            "        if: github.event_name == 'schedule'",
            "        if: github.event_name == 'push'",
        ),
        ('test "$GITHUB_REF" = "refs/heads/main"', 'test "$GITHUB_REF" != "refs/heads/main"'),
        ('test "$live_main" = "$GITHUB_SHA"', 'test "$live_main" != "$GITHUB_SHA"'),
        ('/security.yml@refs/heads/main"', '/security.yml@refs/heads/untrusted"'),
    ],
)
def test_mutating_exact_scheduled_security_admission_fails_closed(old: str, new: str) -> None:
    source = SECURITY.read_text(encoding="utf-8")
    assert old in source
    with pytest.raises(ValueError):
        contract._verify_security_evidence_workflow(source.replace(old, new, 1))
