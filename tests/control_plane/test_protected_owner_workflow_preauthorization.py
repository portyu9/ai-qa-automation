"""Exact-byte trust boundary for the staged, signed owner workflow pin migration."""
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


def _both_reviewed_workflows() -> tuple[str, str]:
    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert source.count(OLD_PIN) + source.count(NEW_PIN) == 1
    if OLD_PIN in source:
        old_text, new_text = source, source.replace(OLD_PIN, NEW_PIN)
    else:
        new_text, old_text = source, source.replace(NEW_PIN, OLD_PIN)
    return old_text, new_text


def test_only_single_signed_pin_transition_is_preauthorized() -> None:
    old_text, new_text = _both_reviewed_workflows()
    # The immutable Git identities live solely in the trusted verifier, not in
    # test-source copies. Recompute each candidate from actual workflow bytes.
    assert verifier._trusted_auto._base._git_blob_sha1(old_text) == (
        verifier.EXPECTED_PROTECTED_MAINTENANCE_WORKFLOW_BLOB_SHA
    )
    assert verifier._trusted_auto._base._git_blob_sha1(new_text) == (
        verifier.PREAUTHORIZED_PROTECTED_MAINTENANCE_WORKFLOW_BLOB_SHA
    )
    verifier._require_reviewed_protected_owner_authorizer(old_text)
    verifier._require_reviewed_protected_owner_authorizer(new_text)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("permissions:", "permissions: # unreviewed"),
        lambda text: text.replace(NEW_PIN, NEW_PIN + " # unreviewed"),
        lambda text: text.replace("name:", "name: # unreviewed", 1),
        lambda text: text + "\n# unreviewed workflow mutation\n",
    ],
)
def test_other_owner_workflow_bytes_fail_closed(mutation) -> None:
    _, new_text = _both_reviewed_workflows()
    bad = mutation(new_text)
    assert bad != new_text
    with pytest.raises(ValueError, match="protected owner authorizer workflow differs"):
        verifier._require_reviewed_protected_owner_authorizer(bad)
