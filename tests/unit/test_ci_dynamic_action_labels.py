from __future__ import annotations

from pathlib import Path

import pytest

import scripts.ci_contract_base as base
import scripts.verify_ci_contract as contract

ROOT = Path(__file__).resolve().parents[2]
OLD_UPLOAD = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"  # pragma: allowlist secret
NEW_UPLOAD = "cf430e030ddbb5b0abf93d22962f4752f3646cd9"  # pragma: allowlist secret


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
            upgraded.replace(
                f"      - name: {base.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n        if: always()",
                f"      - name: {base.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n        if: ${{ false }}",
                1,
            )
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


def test_security_autoheal_download_pin_is_dynamic_but_strictly_scoped() -> None:
    workflow = (ROOT / ".github/workflows/security-autoheal.yml").read_text(encoding="utf-8")
    base._verify_action_revisions(
        {
            path.name: path.read_text(encoding="utf-8")
            for path in (ROOT / ".github/workflows").glob("*.yml")
        }
    )
    reconcile = base._job_block(workflow, "reconcile")
    restore = base._step_block(
        reconcile, "Restore exact-run route plan from prior read-only job"
    )
    pin = list(base.ACTION_PIN_RE.finditer(base._semantic_text(restore)))
    assert len(pin) == 1
    assert pin[0].group("action") == "actions/download-artifact"
    current_sha = pin[0].group("sha")
    current_version = pin[0].group("version")
    replacement_sha = ("a" if current_sha[0] != "a" else "b") * 40
    new_pin = f"actions/download-artifact@{replacement_sha} # v8.42"
    original_pin = f"actions/download-artifact@{current_sha} # v{current_version}"
    updated = workflow.replace(original_pin, new_pin)
    assert updated != workflow
    contract._verify_security_autoheal_workflow(updated)

    # A single altered pin must be refused by the independent cross-workflow
    # version/SHA consistency check (not self-authorized by the updated step).
    workflows = {
        path.name: path.read_text(encoding="utf-8")
        for path in (ROOT / ".github/workflows").glob("*.yml")
    }
    workflows["security-autoheal.yml"] = updated
    with pytest.raises(ValueError, match="inconsistent pin/version authority"):
        base._verify_action_revisions(workflows)

    with pytest.raises(ValueError, match="requires one immutable reviewed"):
        contract._verify_security_autoheal_workflow(
            workflow.replace(original_pin, f"example/download-artifact@{replacement_sha} # v8.42")
        )
    with pytest.raises(ValueError, match="requires one immutable reviewed"):
        contract._verify_security_autoheal_workflow(
            workflow.replace(original_pin, f"actions/download-artifact@{replacement_sha} # v7")
        )
    with pytest.raises(ValueError, match="requires one immutable reviewed"):
        contract._verify_security_autoheal_workflow(
            workflow.replace(original_pin, "actions/download-artifact@not-a-sha # v8")
        )
    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        contract._verify_security_autoheal_workflow(
            updated.replace(
                "          artifact-ids: ${{ needs.route-plan.outputs.artifact-id }}",
                "          artifact-ids: 42",
            )
        )
