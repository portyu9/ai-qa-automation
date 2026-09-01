from __future__ import annotations

from pathlib import Path

from scripts import auto_trusted_preflight
import scripts.verify_ci_contract as ci_contract
from scripts.trusted_gate_service import core as external_gate

ROOT = Path(__file__).resolve().parents[2]


def test_ordinary_ci_contains_no_retired_protected_manifest_authority() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "repository_dispatch" not in text
    assert "github.event.client_payload" not in text
    assert "protected_manifest" not in text
    assert "Validate trusted dispatch subject syntax" not in text
    assert "Verify trusted control-plane subject" not in text
    assert "Trusted PR Gate Reporter" not in text


def test_protected_root_sets_are_identical_across_trusted_paths() -> None:
    automatic = tuple(ci_contract.TRUSTED_AUTO_PROTECTED_PATHS)
    preflight = tuple(auto_trusted_preflight.PROTECTED_PATHS)
    external = tuple(external_gate.PROTECTED_PATHS)

    assert automatic == preflight == external
    assert ".gitattributes" in automatic


def test_automatic_subject_guard_checks_every_protected_root() -> None:
    text = (ROOT / ".github" / "workflows" / "trusted-pr-auto.yml").read_text(encoding="utf-8")
    subject_guard = ci_contract._job_block(text, "subject-guard")

    for path in auto_trusted_preflight.PROTECTED_PATHS:
        assert f"            {path}\n" in subject_guard

    assert 'test "$base_oid" = "$subject_oid"' in subject_guard
