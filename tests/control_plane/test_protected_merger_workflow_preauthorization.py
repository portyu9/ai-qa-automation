"""Exact byte-identity contract for the native signed terminal merger pin migration."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_ci_contract")

WORKFLOW_PATH = ROOT / ".github" / "workflows" / "protected-maintenance-merge.yml"
OLD_PIN = "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"
NEW_PIN = "uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0"


def _both_reviewed_workflows() -> tuple[str, str]:
    original = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert original.count(OLD_PIN) + original.count(NEW_PIN) == 1
    if OLD_PIN in original:
        old_text, new_text = original, original.replace(OLD_PIN, NEW_PIN)
    else:
        new_text, old_text = original, original.replace(NEW_PIN, OLD_PIN)
    return old_text, new_text


def test_only_exact_native_signed_merger_transition_is_preauthorized() -> None:
    old_text, new_text = _both_reviewed_workflows()
    # Reviewed full Git blob identities reside ONLY in the verifier's authority.
    assert verifier._trusted_auto._base._git_blob_sha1(old_text) == (
        verifier.EXPECTED_PROTECTED_MAINTENANCE_MERGE_WORKFLOW_BLOB_SHA
    )
    assert verifier._trusted_auto._base._git_blob_sha1(new_text) == (
        verifier.PREAUTHORIZED_PROTECTED_MAINTENANCE_MERGE_WORKFLOW_BLOB_SHA
    )
    verifier._require_reviewed_protected_terminal_merger(old_text)
    verifier._require_reviewed_protected_terminal_merger(new_text)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("permissions:", "permissions: # unreviewed"),
        lambda text: text.replace(NEW_PIN, NEW_PIN + " # unreviewed"),
        lambda text: text.replace("name:", "name: # unreviewed", 1),
        lambda text: text + "\n# unreviewed workflow mutation\n",
    ],
)
def test_unreviewed_merger_bytes_fail_closed(mutation) -> None:
    _, new_text = _both_reviewed_workflows()
    bad = mutation(new_text)
    assert bad != new_text
    with pytest.raises(ValueError, match="protected maintenance merger workflow differs"):
        verifier._require_reviewed_protected_terminal_merger(bad)
