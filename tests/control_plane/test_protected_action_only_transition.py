"""Exact-byte protected workflow action-only transition assurance.

These tests exercise the source-only CI contract; a passing test is never
substitute proof of signed upstream release, native bot identity, owner veto,
or protected merge. Test fixtures track the *currently proposed* workflow pin
rather than freezing a release forever, preventing another Dependabot deadlock.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

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
PIN_RE = re.compile(
    r"^        uses: (?P<action>actions/(?:checkout|setup-python))@"
    r"(?P<sha>[0-9a-f]{40}) # v"
    r"(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)$",
    re.MULTILINE,
)


def _pin(source: str, action: str) -> re.Match[str]:
    rows = [m for m in PIN_RE.finditer(source) if m.group("action") == action]
    assert len(rows) == 1
    return rows[0]


def _repin(source: str, old_line: str, new_line: str) -> str:
    assert source.count(old_line) == 1 and new_line != old_line
    return source.replace(old_line, new_line, 1)


def _candidate(pin: re.Match[str], *, sha: str, bump: str) -> str:
    old = tuple(int(pin.group(i)) for i in ("major", "minor", "patch"))
    if bump == "minor":
        version = (old[0], old[1] + 1, 0)
    elif bump == "major":
        version = (old[0] + 1, 0, 0)
    elif bump == "same":
        version = old
    else:
        raise AssertionError("unreviewed fixture bump")
    return f"        uses: {pin.group('action')}@{sha} # v" + ".".join(str(v) for v in version)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_current_source_is_still_byte_bound_to_reviewed_original(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    assert re.fullmatch(r"[0-9a-f]{40}", accepted_sha)
    _pin(source, "actions/checkout")
    _pin(source, "actions/setup-python")
    verify(source)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_only_future_monotonic_pin_lines_are_admitted(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    checkout = _pin(source, "actions/checkout")
    python = _pin(source, "actions/setup-python")
    variants = (
        (_candidate(checkout, sha="a" * 40, bump="minor"), python.group(0)),
        (checkout.group(0), _candidate(python, sha="b" * 40, bump="minor")),
        (
            _candidate(checkout, sha="c" * 40, bump="minor"),
            _candidate(python, sha="d" * 40, bump="minor"),
        ),
        (
            _candidate(checkout, sha="e" * 40, bump="same"),
            _candidate(python, sha="f" * 40, bump="same"),
        ),
        (
            _candidate(checkout, sha="a" * 40, bump="major"),
            _candidate(python, sha="b" * 40, bump="major"),
        ),
    )
    for next_checkout, next_python in variants:
        candidate = source
        if next_checkout != checkout.group(0):
            candidate = _repin(candidate, checkout.group(0), next_checkout)
        if next_python != python.group(0):
            candidate = _repin(candidate, python.group(0), next_python)
        assert candidate != source
        # Source-only source shape never waives the independent upstream proof.
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
    ),
)
def test_invalid_pin_transition_is_rejected(name, accepted_sha, verify, bad_pin):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    original = _pin(source, "actions/setup-python")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(_repin(source, original.group(0), bad_pin))


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
@pytest.mark.parametrize(
    "mutate",
    (
        lambda s: s.replace("permissions:", "permissions: # changed", 1),
        lambda s: s.replace("  cancel-in-progress: false", "  cancel-in-progress: true", 1),
        lambda s: s.replace("name:", "name: # changed", 1),
        lambda s: s.replace("    timeout-minutes:", "    timeout-minutes: # changed", 1),
        lambda s: s.replace(
            "          persist-credentials: false", "          persist-credentials: true", 1
        ),
        lambda s: s.replace("GITHUB_TOKEN:", "TOKEN:", 1),
        lambda s: s + "\n# extra byte\n",
        lambda s: s.replace("  schedule:", "  workflow_dispatch:\n  schedule:", 1),
        lambda s: s.replace("    steps:", "    steps:\n      - run: echo untrusted", 1),
        lambda s: s.replace("    runs-on: ubuntu-24.04", "    runs-on: self-hosted", 1),
    ),
)
def test_prospective_pin_change_cannot_mask_other_workflow_bytes(
    name, accepted_sha, verify, mutate
):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    existing = _pin(source, "actions/setup-python")
    candidate = _repin(source, existing.group(0), _candidate(existing, sha="b" * 40, bump="minor"))
    altered = mutate(candidate)
    if altered == candidate:
        pytest.skip("selected authority is not present in this distinct workflow")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(altered)


@pytest.mark.parametrize("name, accepted_sha, verify", SOURCES)
def test_extra_or_duplicated_action_pins_rejected(name, accepted_sha, verify):
    source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
    existing = _pin(source, "actions/setup-python")
    extra = _candidate(existing, sha="b" * 40, bump="minor")
    candidate = _repin(source, existing.group(0), extra)
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(candidate + "\n" + extra + "\n")
    with pytest.raises(ValueError, match="differs from reviewed authority"):
        verify(
            candidate.replace(extra, extra + "\n" + _pin(source, "actions/checkout").group(0), 1)
        )
