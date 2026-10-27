"""Exact native scheduled CI is certified, and unreviewed changes fail closed."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_ci_contract")
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def _source() -> str:
    return CI_PATH.read_text(encoding="utf-8")


def test_accepted_schedule_exact_shape() -> None:
    source = _source()
    evidence = verifier._verify_ordinary_ci_workflow(source)
    assert evidence["triggers"] == [
        "merge_group",
        "pull_request",
        "push",
        "schedule",
        "workflow_call",
        "workflow_dispatch",
    ]
    assert verifier._trusted_auto._base._workflow_structure_sha1(source) == (
        verifier.EXPECTED_ORDINARY_CI_WORKFLOW_BLOB_SHA
    )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ('    - cron: "13 11,23 * * *"', '    - cron: "*/5 * * * *"'),
        (
            "        if: github.event_name == 'schedule'",
            "        if: github.event_name == 'pull_request'",
        ),
        ('test "$GITHUB_REF" = "refs/heads/main"', 'test "$GITHUB_REF" != "refs/heads/main"'),
        ('test "$live_main" = "$GITHUB_SHA"', 'test "$live_main" != "$GITHUB_SHA"'),
        ('/ci.yml@refs/heads/main"', '/ci.yml@refs/heads/untrusted"'),
    ],
)
def test_unreviewed_schedule_mutation_rejected(needle: str, replacement: str) -> None:
    current = _source()
    assert needle in current
    mutated = current.replace(needle, replacement, 1)
    with pytest.raises(ValueError):
        verifier._verify_ordinary_ci_workflow(mutated)
