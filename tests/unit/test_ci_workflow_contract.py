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
    automatic = result["workflows"]["automatic"]
    assert automatic["required_gate"] == "Required PR Gate"
    assert automatic["documentation_integrity"] == "required-via-supply-chain"
    assert automatic["mermaid_render"] == "required-via-supply-chain"
    assert automatic["build_provenance_subject"] == "CI_SUBJECT_SHA/isolated-git-view"
    assert automatic["archive_attribute_authority"] == "versioned-tree-only"
    assert automatic["sbom_lineage"] == "parent-digest-bound-and-bracketed"
    assert automatic["supply_chain_evidence"] == "pinned-upload-action"
    assert automatic["subject"] == "github.sha-or-owner-default-branch-dispatch-exact-merge-sha"
    assert automatic["reporter_identity"] == "dedicated-github-app-installation-token"
    assert automatic["trusted_status"]["authorization"] == (
        "owner-default-branch-repository-dispatch-plus-main-only-environment"
    )
    assert automatic["trusted_status"]["write_authority"] == (
        "dedicated-github-app:statuses-write"
    )
    assert automatic["protected_manifest"]["mode"] == (
        "exact-owner-dispatch-object-manifest"
    )
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

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_workflow_dispatch_for_trusted_validation(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  repository_dispatch:\n    types: [trusted-pr-validation]\n"
    assert marker in text
    path.write_text(
        text.replace(marker, "  workflow_dispatch:\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unreviewed_repository_dispatch_event_type(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "    types: [trusted-pr-validation]\n"
    assert marker in text
    path.write_text(text.replace(marker, "    types: [arbitrary]\n", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="trigger/owner-dispatch contract"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_client_payload_subject_bypass(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = (
        "  CI_SUBJECT_SHA: ${{ github.event_name == 'repository_dispatch' "
        "&& github.event.client_payload.expected_merge_sha || github.sha }}\n"
    )
    assert marker in text
    path.write_text(
        text.replace(marker, "  CI_SUBJECT_SHA: ${{ github.sha }}\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CI_SUBJECT_SHA must select only"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_write_permission(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("  contents: read", "  contents: write", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="write permission is forbidden outside trusted reporter"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_secret_in_validation_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = '  PIP_DISABLE_PIP_VERSION_CHECK: "1"\n'
    assert marker in text
    path.write_text(
        text.replace(marker, marker + "  BAD: ${{ secrets.ANTHROPIC_API_KEY }}\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden validation authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_second_trusted_app_private_key_consumer(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          TRUSTED_GATE_APP_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}\n"
    assert text.count(marker) == 1
    path.write_text(
        text.replace(
            marker,
            marker + "          SECOND_PRIVATE_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="private key must be scoped to exactly one reporter step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_native_status_write_in_trusted_reporter(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "    permissions:\n      contents: read\n"
    assert marker in ci_contract._job_block(text, "trusted-status")
    path.write_text(
        text.replace(marker, marker + "      statuses: write\n", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must not own trusted status write authority"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_missing_trusted_gate_environment(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "    environment:\n      name: trusted-pr-gate\n      deployment: false\n"
    assert marker in text
    path.write_text(text.replace(marker, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="trusted reporter is missing reviewed fragment"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_weakened_protected_manifest_comparison(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          if normalized != observed:\n"
    assert marker in text
    path.write_text(text.replace(marker, "          if False:\n", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="protected change manifest contract"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_trusted_reporter_without_main_owner_guard(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    exact = (
        "    if: ${{ always() && github.event_name == 'repository_dispatch' "
        "&& github.ref == 'refs/heads/main' && github.actor == github.repository_owner }}\n"
    )
    assert exact in text
    path.write_text(
        text.replace(
            exact,
            "    if: ${{ always() && github.event_name == 'repository_dispatch' }}\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="trusted reporter is missing reviewed fragment"):
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


def test_ci_contract_rejects_unbound_validation_checkout(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "ref: ${{ env.CI_SUBJECT_SHA }}"
    assert text.count(marker) == ci_contract.EXPECTED_AUTOMATIC_SUBJECT_CHECKOUT_COUNT
    path.write_text(text.replace(marker, "ref: main", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="every validation checkout must bind"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_unbound_trusted_reporter_checkout(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "ref: ${{ github.sha }}"
    assert text.count(marker) == 1
    path.write_text(text.replace(marker, "ref: main", 1), encoding="utf-8")

    with pytest.raises(ValueError, match=r"trusted reporter must be the sole github\.sha checkout"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_mutable_head_for_reproducible_archive(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    original = (
        '/usr/bin/git -c core.attributesFile=/dev/null archive --format=tar "$CI_SUBJECT_SHA" '
        '| env -i PATH="$PATH" /usr/bin/tar -xf - -C "$build_a"'
    )
    replacement = (
        "/usr/bin/git -c core.attributesFile=/dev/null archive --format=tar HEAD "
        '| env -i PATH="$PATH" /usr/bin/tar -xf - -C "$build_a"'
    )
    text = path.read_text(encoding="utf-8")
    assert original in text
    path.write_text(text.replace(original, replacement, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_reenabled_replace_objects_for_archive(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    archive_marker = " GIT_ATTR_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1"
    assert archive_marker in text
    path.write_text(
        text.replace(archive_marker, " GIT_ATTR_NOSYSTEM=1", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removed_system_attribute_isolation(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert " GIT_ATTR_NOSYSTEM=1" in text
    path.write_text(text.replace(" GIT_ATTR_NOSYSTEM=1", "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_ambient_global_archive_attributes(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert " -c core.attributesFile=/dev/null archive" in text
    path.write_text(
        text.replace(" -c core.attributesFile=/dev/null archive", " archive", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_checkout_git_dir_for_archive(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert 'GIT_DIR="$git_view" GIT_OBJECT_DIRECTORY="$git_object_directory"' in text
    path.write_text(
        text.replace(
            'GIT_DIR="$git_view" GIT_OBJECT_DIRECTORY="$git_object_directory"',
            'GIT_DIR=.git GIT_OBJECT_DIRECTORY="$git_object_directory"',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_nonempty_git_template_authority(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert '--template="$git_template"' in text
    path.write_text(text.replace(' --template="$git_template"', "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_ambient_tar_options_for_archive_extraction(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    clean_tar = 'env -i PATH="$PATH" /usr/bin/tar -xf - -C "$build_a"'
    assert clean_tar in text
    path.write_text(
        text.replace(clean_tar, '/usr/bin/tar -xf - -C "$build_a"', 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_mutable_head_for_build_manifest_subject(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    original = '--expected-source-sha "$CI_SUBJECT_SHA"'
    assert original in text
    path.write_text(
        text.replace(original, '--expected-source-sha "$(git rev-parse HEAD)"', 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact reviewed validation-subject-bound step"):
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
