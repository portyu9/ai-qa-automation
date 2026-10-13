from __future__ import annotations

from pathlib import Path

import pytest

import scripts.ci_contract_base as base

ROOT = Path(__file__).resolve().parents[2]
OLD_UPLOAD = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
NEW_UPLOAD = "cf430e030ddbb5b0abf93d22962f4752f3646cd9"


def test_signed_upload_patch_retains_exact_supply_chain_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    original = base._job_block(workflow, "supply-chain")
    upgraded = original.replace(
        f"actions/upload-artifact@{OLD_UPLOAD} # v7.0.1",
        f"actions/upload-artifact@{NEW_UPLOAD} # v7.0.2",
    )
    assert upgraded != original
    monkeypatch.setitem(base.EXPECTED_ACTION_SHAS, "actions/upload-artifact", NEW_UPLOAD)
    base._require_exact_supply_chain_upload_step(upgraded)

    # A version label does not authorize a different action, source pin,
    # missing evidence, or a disabled upload.
    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        base._require_exact_supply_chain_upload_step(
            upgraded.replace("        if: always()", "        if: ${{ false }}", 1)
        )
    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        base._require_exact_supply_chain_upload_step(
            upgraded.replace("          retention-days: 30", "          retention-days: 1", 1)
        )
    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        base._require_exact_supply_chain_upload_step(original)


def test_dynamic_action_label_rejects_unbound_sha_and_spoofed_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = f"      - name: upload\n        uses: actions/upload-artifact@{NEW_UPLOAD} # v7.0.2"
    monkeypatch.setitem(base.EXPECTED_ACTION_SHAS, "actions/upload-artifact", NEW_UPLOAD)
    assert base._version_of_exact_reviewed_action_step(valid, "actions/upload-artifact") == "7.0.2"
    with pytest.raises(ValueError, match="exact step action identity or SHA"):
        base._version_of_exact_reviewed_action_step(
            valid.replace(NEW_UPLOAD, OLD_UPLOAD), "actions/upload-artifact"
        )
    with pytest.raises(ValueError, match="exact step action identity or SHA"):
        base._version_of_exact_reviewed_action_step(
            valid.replace("actions/upload-artifact", "example/action"),
            "actions/upload-artifact",
        )
