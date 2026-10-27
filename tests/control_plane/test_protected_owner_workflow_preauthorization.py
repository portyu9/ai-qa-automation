"""Retire the old protected owner authorization action pin trust after signed #419 merge."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_ci_contract")

WORKFLOW_PATH = ROOT / ".github" / "workflows" / "protected-maintenance-authorizer.yml"
OLD_PIN = "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"
NEW_PIN = "uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0"


def _accepted_workflow() -> str:
    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert source.count(NEW_PIN) == 1
    assert OLD_PIN not in source
    return source


def test_only_single_accepted_native_workflow_is_trusted() -> None:
    accepted = _accepted_workflow()
    assert verifier._trusted_auto._base._git_blob_sha1(accepted) == (
        verifier.EXPECTED_PROTECTED_MAINTENANCE_WORKFLOW_BLOB_SHA
    )
    verifier._require_reviewed_protected_owner_authorizer(accepted)


def test_superseded_owner_version_is_rejected() -> None:
    accepted = _accepted_workflow()
    retired = accepted.replace(NEW_PIN, OLD_PIN)
    assert retired != accepted
    with pytest.raises(ValueError, match="protected owner authorizer workflow differs"):
        verifier._require_reviewed_protected_owner_authorizer(retired)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("permissions:", "permissions: # unreviewed"),
        lambda text: text.replace(NEW_PIN, NEW_PIN + " # unreviewed"),
        lambda text: text.replace("name:", "name: # unreviewed", 1),
        lambda text: text + "\n# unreviewed workflow mutation\n",
    ],
)
def test_unreviewed_workflow_bytes_fail_closed(mutation) -> None:
    accepted = _accepted_workflow()
    bad = mutation(accepted)
    assert bad != accepted
    with pytest.raises(ValueError, match="protected owner authorizer workflow differs"):
        verifier._require_reviewed_protected_owner_authorizer(bad)
