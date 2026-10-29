"""Fail-closed exact-byte protected workflow action pin transition assurance.

These fixtures exercise the *source-only* CI contract.  Upstream signature,
native Dependabot identity, owner veto, and exact protected merge remain separate,
mandatory independent trusted-main gates; this test never fakes those gates.
"""

from __future__ import annotations

import importlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
verifier = importlib.import_module("verify_ci_contract")

SOURCES = (
    (
        "protected-maintenance-authorizer.yml",
        verifier.EXPECTED_PROTECTED_MAINTENANCE_WORKFLOW_BLOB_SHA,
        verifier._require_reviewed_protected_owner_authorizer,
    ),
    (
        "protected-maintenance-merge.yml",
        verifier.EXPECTED_PROTECTED_MAINTENANCE_MERGE_WORKFLOW_BLOB_SHA,
        verifier._require_reviewed_protected_terminal_merger,
    ),
)
CHECKOUT_OLD = (
    "        uses: actions/checkout@"
    "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
)
PYTHON_OLD = (
    "        uses: actions/setup-python@"
    "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0"
)
CHECKOUT_NEW = "        uses: actions/checkout@" + "a" * 40 + " # v7.1.0"
PYTHON_NEW = "        uses: actions/setup-python@" + "b" * 40 + " # v7.2.0"


def _repin(text: str, before: str, after: str) -> str:
    assert text.count(before) == 1
    assert after != before
    return text.replace(before, after, 1)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_accepted_complete_blob_remains_exact(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    assert verifier._trusted_auto._base._git_blob_sha1(source) == accepted_sha
    assert source.count(CHECKOUT_OLD) == source.count(PYTHON_OLD) == 1
    verify(source)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_only_future_monotonic_action_pin_lines_are_admitted(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    for after_checkout, after_python in (
        (CHECKOUT_NEW, PYTHON_OLD),
        (CHECKOUT_OLD, PYTHON_NEW),
        (CHECKOUT_NEW, PYTHON_NEW),
        (
            "        uses: actions/checkout@" + "c" * 40 + " # v7.0.1",
            "        uses: actions/setup-python@" + "d" * 40 + " # v7.1.0",
        ),
        (
            "        uses: actions/checkout@" + "e" * 40 + " # v8.0.0",
            "        uses: actions/setup-python@" + "f" * 40 + " # v8.0.0",
        ),
    ):
        candidate = source
        if after_checkout != CHECKOUT_OLD:
            candidate = _repin(candidate, CHECKOUT_OLD, after_checkout)
        if after_python != PYTHON_OLD:
            candidate = _repin(candidate, PYTHON_OLD, after_python)
        assert verifier._trusted_auto._base._git_blob_sha1(candidate) != accepted_sha
        # Source-only admission does not waive independently signed upstream,
        # native Dependabot commit, Trusted PR Gate, or owner/merge checks.
        verify(candidate)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
@pytest.mark.parametrize(
    "bad_pin",
    (
        "        uses: actions/setup-python@" + "b" * 40 + " # v7.0.0",
        "        uses: actions/setup-python@" + "b" * 40 + " # v7.01.0",
        "        uses: actions/setup-python@" + "b" * 40 + " # v7.2",
        "        uses: actions/setup-python@" + "b" * 40 + " # v1000.0.0",
        "        uses: actions/setup-python@" + "b" * 40 + " # v7.2.0 extra",
        "        uses: actions/setup-python@" + "B" * 40 + " # v7.2.0",
        "        uses: evil/setup-python@" + "b" * 40 + " # v7.2.0",
        "        uses: actions/setup-python@" + "b" * 39 + " # v7.2.0",
        "        uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.2.0",
    ),
)
def test_invalid_pin_transition_is_rejected(name, accepted_sha, verify, bad_pin):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(_repin(source, PYTHON_OLD, bad_pin))


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
@pytest.mark.parametrize(
    "mutate",
    (
        lambda s: s.replace("permissions:", "permissions: # changed", 1),
        lambda s: s.replace("  cancel-in-progress: false", "  cancel-in-progress: true", 1),
        lambda s: s.replace("name:", "name: # changed", 1),
        lambda s: s.replace("    timeout-minutes:", "    timeout-minutes: # changed", 1),
        lambda s: s.replace("          persist-credentials: false", "          persist-credentials: true", 1),
        lambda s: s.replace("GITHUB_TOKEN:", "TOKEN:", 1),
        lambda s: s + "\n# extra byte\n",
        lambda s: s.replace(CHECKOUT_NEW, CHECKOUT_NEW + " # changed", 1),
        lambda s: s.replace("  schedule:", "  workflow_dispatch:\n  schedule:", 1),
        lambda s: s.replace("    steps:", "    steps:\n      - run: echo untrusted", 1),
        lambda s: s.replace("    runs-on: ubuntu-24.04", "    runs-on: self-hosted", 1),
    ),
)
def test_prospective_pin_change_cannot_mask_other_workflow_bytes(
    name, accepted_sha, verify, mutate,
):
    original = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    signed_pin_shape = _repin(original, PYTHON_OLD, PYTHON_NEW)
    changed = mutate(signed_pin_shape)
    # Mutation must actually alter the fixture to avoid vacuous assurances.
    if changed == signed_pin_shape:
        pytest.skip("selected authority is not present in this distinct workflow")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(changed)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_extra_or_duplicated_action_pins_rejected(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    modified = _repin(source, PYTHON_OLD, PYTHON_NEW)
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(modified + "\n" + PYTHON_NEW + "\n")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(modified.replace(PYTHON_NEW, PYTHON_NEW + "\n" + CHECKOUT_OLD, 1))
