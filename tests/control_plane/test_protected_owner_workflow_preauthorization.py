"""Pin-aware whole-blob regression: reject retired and non-action workflow bytes."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_ci_contract")

WORKFLOW_PATH = ROOT / ".github" / "workflows" / "protected-maintenance-authorizer.yml"
OLD_PIN = "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0"
PIN_RE = re.compile(r"^        uses: actions/setup-python@[0-9a-f]{40} # v[0-9]+(?:\.[0-9]+){2}$", re.MULTILINE)


def _accepted_workflow() -> str:
    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert len(PIN_RE.findall(source)) == 1
    assert OLD_PIN not in source
    return source


def test_only_single_accepted_native_workflow_is_trusted() -> None:
    accepted = _accepted_workflow()
    verifier._require_reviewed_protected_owner_authorizer(accepted)


def test_superseded_owner_version_is_rejected() -> None:
    accepted = _accepted_workflow()
    retired = accepted.replace(PIN_RE.search(accepted).group(0).strip(), OLD_PIN)
    assert retired != accepted
    with pytest.raises(ValueError, match="protected owner authorizer workflow differs"):
        verifier._require_reviewed_protected_owner_authorizer(retired)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda text: text.replace("permissions:", "permissions: # unreviewed"),
        lambda text: text.replace("uses: actions/setup-python@", "uses: evil/setup-python@", 1),
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
