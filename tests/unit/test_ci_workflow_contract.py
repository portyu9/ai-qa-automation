from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract
import scripts.verify_supply_chain as supply_chain

ROOT = Path(__file__).resolve().parents[2]


def _copy_workflows(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.parent.mkdir(parents=True)
    shutil.copytree(ROOT / ".github" / "workflows", workflow_dir)
    return root


def test_repository_ci_contract_is_self_consistent() -> None:
    result = ci_contract.verify_ci_contract(ROOT)

    assert result["result"] == "PASS"
    assert result["schema_version"] == 1
    assert result["workflows"]["automatic"]["required_gate"] == "Required PR Gate"
    assert (
        result["workflows"]["automatic"]["documentation_integrity"] == "required-via-supply-chain"
    )
    assert result["workflows"]["automatic"]["mermaid_render"] == "required-via-supply-chain"
    assert result["workflows"]["automatic"]["build_provenance_subject"] == "github.sha"
    assert result["workflows"]["automatic"]["supply_chain_evidence"] == "pinned-upload-action"
    assert result["workflows"]["automatic"]["secrets"] is False
    assert result["workflows"]["manual"]["credentialed_model"] == "manual-only"


def test_ci_action_authority_matches_supply_chain_verifier() -> None:
    assert ci_contract.EXPECTED_ACTION_SHAS == supply_chain.EXPECTED_ACTION_SHAS


def test_manual_model_credential_scope_is_narrow() -> None:
    text = (ROOT / ".github" / "workflows" / "manual-validation.yml").read_text(encoding="utf-8")
    model = ci_contract._semantic_text(ci_contract._job_block(text, "model-smoke"))

    assert "    if: ${{ inputs.run_model && github.ref == 'refs/heads/main' }}" in model
    assert "    environment: credentialed-validation" in model
    assert "Require main branch for credentialed validation" in model
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in model
    assert "\n    env:\n      ANTHROPIC_API_KEY:" not in model
    assert model.count("${{ secrets.ANTHROPIC_API_KEY }}") == 2

    main_guard = model.index("Require main branch for credentialed validation")
    install = model.index("Install hash-locked project environment")
    first_secret = model.index("${{ secrets.ANTHROPIC_API_KEY }}")
    assert main_guard < install < first_secret


def test_ci_contract_rejects_pull_request_target_even_with_spoof_comment(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        "  pull_request:\n",
        "  # pull_request:\n  pull_request_target:\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="automatic trigger set"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_write_permission(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("  contents: read", "  contents: write", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="permissions must be exactly contents: read"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_secret_in_automatic_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    path.write_text(
        path.read_text(encoding="utf-8") + "\nenv:\n  BAD: ${{ secrets.ANTHROPIC_API_KEY }}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden automatic-CI authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_automatic_trigger_in_manual_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "manual-validation.yml"
    text = path.read_text(encoding="utf-8").replace(
        "on:\n  workflow_dispatch:\n",
        "on:\n  workflow_dispatch:\n  pull_request:\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unexpected_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    rogue = root / ".github" / "workflows" / "rogue.yml"
    rogue.write_text("name: rogue\non: push\n", encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected workflow set"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_symlinked_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    workflow_dir = root / ".github" / "workflows"
    external = tmp_path / "external.yml"
    shutil.copyfile(workflow_dir / "ci.yml", external)
    victim = workflow_dir / "ci.yml"
    victim.unlink()
    victim.symlink_to(external)

    with pytest.raises(ValueError, match="regular non-symlink file"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_workflow_directory_symlink(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    workflow_dir = root / ".github" / "workflows"
    real = root / ".github" / "workflows-real"
    workflow_dir.rename(real)
    workflow_dir.symlink_to(real, target_is_directory=True)

    with pytest.raises(ValueError, match="workflow directory is a symlink"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_enforces_directory_enumeration_bound(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    workflow_dir = root / ".github" / "workflows"
    for index in range(ci_contract.MAX_WORKFLOW_ENTRIES):
        (workflow_dir / f"junk-{index:02d}.txt").write_text("x", encoding="utf-8")

    with pytest.raises(ValueError, match="entry ingestion limit"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unbound_checkout(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("ref: ${{ github.sha }}", "ref: main")
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match=r"every checkout must bind to github\.sha"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_mutable_head_for_reproducible_archive(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        'git archive --format=tar "$GITHUB_SHA" | tar -xf - -C /tmp/aiqa-build-a',
        "git archive --format=tar HEAD | tar -xf - -C /tmp/aiqa-build-a",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed event-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_mutable_head_for_build_manifest_subject(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        '--expected-source-sha "$GITHUB_SHA"',
        '--expected-source-sha "$(git rev-parse HEAD)"',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed event-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_documentation_integrity_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"          {ci_contract.DOCUMENTATION_INTEGRITY_COMMAND}\n",
        "          true\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed script step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fail_open_documentation_step_condition(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"      - name: {ci_contract.DOCUMENTATION_STEP_NAME}\n        run: |\n",
        f"      - name: {ci_contract.DOCUMENTATION_STEP_NAME}\n        if: ${{{{ false }}}}\n        run: |\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed script step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_short_circuited_documentation_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"          {ci_contract.DOCUMENTATION_INTEGRITY_COMMAND}\n",
        f"          true || {ci_contract.DOCUMENTATION_INTEGRITY_COMMAND}\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed script step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_missing_documentation_integrity_evidence_upload(
    tmp_path: Path,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"            {ci_contract.DOCUMENTATION_INTEGRITY_ARTIFACT}\n",
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_mermaid_render_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"          {ci_contract.MERMAID_RENDER_COMMAND}\n",
        "          true\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed script step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_short_circuited_mermaid_command(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"          {ci_contract.MERMAID_RENDER_COMMAND}\n",
        f"          true || {ci_contract.MERMAID_RENDER_COMMAND}\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed script step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_missing_mermaid_render_evidence_upload(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        f"            {ci_contract.MERMAID_VALIDATION_ARTIFACT}\n",
        "",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_disabled_supply_chain_evidence_upload(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    marker = f"      - name: {ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n        if: always()\n"
    replacement = (
        f"      - name: {ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n        if: ${{{{ false }}}}\n"
    )
    text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_noop_supply_chain_evidence_upload(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    marker = (
        f"      - name: {ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n"
        "        if: always()\n"
        "        uses: actions/upload-artifact@"
        f"{ci_contract.EXPECTED_ACTION_SHAS['actions/upload-artifact']} # v7\n"
    )
    replacement = (
        f"      - name: {ci_contract.SUPPLY_CHAIN_UPLOAD_STEP_NAME}\n"
        "        if: always()\n"
        "        run: true\n"
    )
    text = path.read_text(encoding="utf-8").replace(marker, replacement, 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed pinned action step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fail_open_required_gate_dependency(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("      - security\n", "", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="does not depend on security"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fail_open_required_gate_result_check(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        'test "${{ needs.security.result }}" = "success"',
        'test "${{ needs.security.result }}" != "success"',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed aggregate step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_short_circuited_required_gate_result_check(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        'test "${{ needs.security.result }}" = "success"',
        'test "${{ needs.security.result }}" = "success" || true',
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed fail-closed aggregate step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_fail_open_required_gate_condition(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace(
        "  required-gate:\n    name: Required PR Gate\n    if: ${{ always() }}\n",
        "  required-gate:\n    name: Required PR Gate\n    if: ${{ success() }}\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match=r"must execute with if: always\(\)"):
        ci_contract.verify_ci_contract(root)
