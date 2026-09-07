from __future__ import annotations

from pathlib import Path

import scripts.verify_ci_contract as ci_contract
from scripts import auto_trusted_preflight
from scripts.trusted_gate_service import core as external_gate

ROOT = Path(__file__).resolve().parents[2]
# Temporary development-window exemption tracked by issue #129. The final governance
# restoration PR must remove this exemption and re-protect all three roots.
_TEMPORARY_ROUTINE_MAINTENANCE_ROOTS = frozenset({".github", "scripts", "tests"})


def test_ordinary_ci_contains_no_retired_protected_manifest_authority() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "repository_dispatch" not in text
    assert "github.event.client_payload" not in text
    assert "protected_manifest" not in text
    assert "Validate trusted dispatch subject syntax" not in text
    assert "Verify trusted control-plane subject" not in text
    assert "Trusted PR Gate Reporter" not in text


def test_routine_and_external_protected_root_partitions_are_explicit() -> None:
    automatic = tuple(ci_contract.TRUSTED_AUTO_PROTECTED_PATHS)
    preflight = tuple(auto_trusted_preflight.PROTECTED_PATHS)
    external = tuple(external_gate.PROTECTED_PATHS)

    assert automatic == preflight
    assert _TEMPORARY_ROUTINE_MAINTENANCE_ROOTS.isdisjoint(automatic)
    assert set(external) - set(automatic) == _TEMPORARY_ROUTINE_MAINTENANCE_ROOTS
    assert set(automatic) < set(external)
    assert ".gitattributes" in automatic


def test_automatic_subject_guard_checks_every_routine_protected_root() -> None:
    text = (ROOT / ".github" / "workflows" / "trusted-pr-auto.yml").read_text(encoding="utf-8")
    subject_guard = ci_contract._job_block(text, "subject-guard")

    for path in auto_trusted_preflight.PROTECTED_PATHS:
        assert f"            {path}\n" in subject_guard

    for path in _TEMPORARY_ROUTINE_MAINTENANCE_ROOTS:
        assert f"            {path}\n" not in subject_guard

    assert 'test "$base_oid" = "$subject_oid"' in subject_guard
