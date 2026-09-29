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
    assert automatic["subject"] == "event-sha-or-explicit-qualified-sha"
    assert automatic["status_write_authority"] == "isolated-generated-maintenance-check-publication"
    assert automatic["protected_maintenance_authority"] == "centralized-app-gate-for-governed-bots"
    assert result["workflows"]["trusted_auto"]["maintenance_authority"] == (
        "autonomous-governed-bots;exact-owner-default-branch-comment-authorization;first-attempt-only;dedicated-app-terminal-writer"
    )
    dependency_governance_pr = result["workflows"]["dependency_governance_pr"]
    assert dependency_governance_pr["triggers"] == ["pull_request"]
    assert dependency_governance_pr["authority"] == "development-evidence-only"
    assert dependency_governance_pr["permissions"] == "contents:read"
    assert dependency_governance_pr["secrets"] == "forbidden"  # pragma: allowlist secret
    assert dependency_governance_pr["mutation"] == "forbidden"
    dependency_governance = result["workflows"]["dependency_governance"]
    assert dependency_governance["reconciliation_concurrency"] == "single-global-mutex"
    assert dependency_governance["promotion_authority"] == (
        "independent-noncertifying-app:contents-write+pull-requests-write:new-subject-only"
    )
    assert dependency_governance["status_merge_authority"] == (
        "exact-synchronized-dependency-lane:current-main-bound:no-secrets:no-author-token:no-check-write"
    )
    assert dependency_governance["triggers"] == [
        "workflow_run",
        "status",
        "schedule",
    ]
    assert dependency_governance["trusted_revision"] == (
        "exact-current-main-or-safe-noop-before-any-non-pr-mutation"
    )
    assert result["workflows"]["manual"]["credentialed_model"] == "manual-only"
    post_merge_ci = result["workflows"]["post_merge_ci"]
    assert (
        post_merge_ci["trigger"]
        == "workflow_run:dependency-governance-or-security-autoheal:completed"
    )
    assert (
        post_merge_ci["authority"] == "exact-governed-main-validation-plus-codeql-sarif-only-write"
    )
    assert post_merge_ci["canonical_codeql"] == "reusable-codeql.yml"
    assert post_merge_ci["security_events_write"] == "isolated-codeql-only"
    assert post_merge_ci["merge_authority"] == "none"
    assert post_merge_ci["trusted_status_authority"] == "none"
    security_autoheal_pr = result["workflows"]["security_autoheal_pr"]
    assert security_autoheal_pr["triggers"] == ["pull_request"]
    assert security_autoheal_pr["authority"] == "development-evidence-only"
    assert security_autoheal_pr["permissions"] == "contents:read"
    assert security_autoheal_pr["secrets"] == "forbidden"  # pragma: allowlist secret
    assert security_autoheal_pr["mutation"] == "forbidden"
    security_autoheal = result["workflows"]["security_autoheal"]
    assert security_autoheal["triggers"] == ["workflow_run", "schedule", "workflow_dispatch"]
    assert security_autoheal["trusted_code_source"] == "accepted-main-only"
    assert security_autoheal["trusted_revision"] == (
        "exact-current-main-or-safe-noop-before-mutation"
    )
    assert security_autoheal["candidate_workflow_execution"] == "forbidden"


def test_security_autoheal_privileged_controller_rejects_pull_request_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace("on:\n", "on:\n  pull_request:\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must remain accepted-main workflow_run/schedule/workflow_dispatch only",
    ):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_privileged_controller_rejects_pr_branch_workflow_wake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal.yml"
    text = path.read_text(encoding="utf-8")
    route_guard = (
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.conclusion == 'success' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        github.event.workflow_run.name == "
        "'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'))\n"
    )
    reconcile_guard = (
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.conclusion == 'success' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        github.event.workflow_run.name == "
        "'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework')))\n"
    )
    assert text.count(route_guard) == 1
    assert text.count(reconcile_guard) == 1
    route_weakened = (
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository)\n"
    )
    reconcile_weakened = (
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository))\n"
    )
    mutated = text.replace(route_guard, route_weakened, 1)
    mutated = mutated.replace(reconcile_guard, reconcile_weakened, 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must accept only successful same-repository main or Trusted PR Auto workflow wakes",
    ):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_requires_exact_current_main_control_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal.yml"
    text = path.read_text(encoding="utf-8")
    exact_ref = "          ref: ${{ github.sha }}\n"
    assert text.count(exact_ref) == 2

    mutated = text.replace(
        exact_ref,
        "          ref: ${{ github.event.repository.default_branch }}\n",
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must pin both planning and mutation to the exact workflow control revision",
    ):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_route_persistence_requires_current_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal.yml"
    text = path.read_text(encoding="utf-8")
    current = (
        "      - name: Persist exact-run route plan before mutation\n"
        "        if: steps.revision.outputs.current == 'true'\n"
    )
    assert current in text
    mutated = text.replace(
        current,
        "      - name: Persist exact-run route plan before mutation\n",
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="route planning and persistence must require exact-current-main admission",
    ):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_revalidates_current_main_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal.yml"
    text = path.read_text(encoding="utf-8")
    command = '          test "$live_main" = "$GITHUB_SHA"\n'
    assert text.count(command) == 1
    mutated = text.replace(command, '          test -n "$live_main"\n', 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="mutation lacks immediate exact-current-main revalidation",
    ):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_pr_self_test_rejects_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal-pr.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace(
        "permissions:\n  contents: read\n", "permissions:\n  contents: write\n", 1
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_PR_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="workflow permissions must be exactly contents: read"):
        ci_contract.verify_ci_contract(root)


def test_security_autoheal_pr_self_test_rejects_privileged_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "security-autoheal-pr.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace("on:\n", "on:\n  workflow_run:\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_SECURITY_AUTOHEAL_PR_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must remain exact pull_request-only development evidence",
    ):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_partitioned_dependency_governance_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = "  group: dependency-governance-global-reconcile\n"
    partitioned = "  group: dependency-governance-${{ github.event.workflow_run.head_branch || github.ref_name || github.run_id }}\n"
    assert current in text
    mutated = text.replace(current, partitioned, 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="reconciliation concurrency contract drifted"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_privileged_controller_rejects_pull_request_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace("on:\n", "on:\n  pull_request:\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must remain accepted-main workflow_run/status/schedule only",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_pr_self_test_rejects_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance-pr.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace(
        "permissions:\n  contents: read\n", "permissions:\n  contents: write\n", 1
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_PR_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="workflow permissions must be exactly contents: read"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_pr_self_test_rejects_privileged_trigger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance-pr.yml"
    text = path.read_text(encoding="utf-8")
    mutated = text.replace("on:\n", "on:\n  workflow_run:\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_PR_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="must remain exact pull_request-only development evidence",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_requires_control_sha_for_general_mutation_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    govern_start = text.index("  govern:\n")
    block = text[govern_start:]
    binding = "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}\n"
    assert binding in block
    mutated_block = block.replace(binding, "", 1)
    mutated = text[:govern_start] + mutated_block
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="general dependency governance must be exact-current-main bound before mutation",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_requires_control_sha(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-merge:\n")
    govern_start = text.index("\n  govern:\n", status_start)
    block = text[status_start:govern_start]
    binding = "    env:\n      GOVERNANCE_CONTROL_SHA: ${{ github.sha }}\n"
    assert binding in block
    mutated_block = block.replace(binding, "", 1)
    mutated = text[:status_start] + mutated_block + text[govern_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="status-target merge must remain exact-revision-bound",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_mutation_requires_exact_current_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    assert "  workflow_dispatch:\n" not in text
    assert "          ref: ${{ github.sha }}\n" in text
    guard = (
        'live=g._live_main_sha(api, config); expected=os.environ["GITHUB_SHA"]; '
        'print("true" if live == expected else "false")'
    )
    assert guard in text

    mutated = text.replace(
        guard,
        'live=g._live_main_sha(api, config); print("true" if live else "false")',
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match=r"dependency-governance\.yml missing reviewed authority invariant",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_rejects_unguarded_author_token_mint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    govern_start = text.index("  govern:\n")
    mint_start = text.index("      - name: Mint independent promotion author token\n", govern_start)
    mint_end = text.index(
        "      - name: Bind promotion author token to reviewed bot identity\n",
        mint_start,
    )
    mint_block = text[mint_start:mint_end]
    guard = "        if: steps.revision.outputs.current == 'true'\n"
    assert guard in mint_block
    mutated_block = mint_block.replace(guard, "", 1)
    mutated = text[:mint_start] + mutated_block + text[mint_end:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="mutation-capable steps must require exact-current-main admission",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_rejects_revision_guard_moved_out_of_govern_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    govern_start = text.index("  govern:\n")
    guard_start = text.index(
        "      - name: Verify exact current-main governance revision before mutation\n",
        govern_start,
    )
    guard_end = text.index("      - name: Capture Python 3.11 resolver\n", guard_start)
    guard_block = text[guard_start:guard_end]
    assert guard_block

    status_start = text.index("  status-sync:\n")
    status_insert = text.index("    steps:\n", status_start) + len("    steps:\n")
    without_guard = text[:guard_start] + text[guard_end:]
    mutated = without_guard[:status_insert] + guard_block + without_guard[status_insert:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="general dependency governance must be exact-current-main bound before mutation",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_post_gate_handoff_is_status_driven_and_acyclic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    assert "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL]\n" in text
    assert "  status:\n" in text
    assert "'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework'" not in text
    assert "      github.event.context == 'Trusted PR Gate' &&\n" in text
    assert "      needs.status-sync.result == 'success' &&\n" in text
    assert "      needs.status-sync.outputs.pr_number != '' &&\n" in text
    assert "      needs.status-sync.outputs.lane != ''\n" in text
    assert (
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n"
        "        startsWith(github.event.workflow_run.head_branch, "
        "'automation/dependency-promotion-')))\n" in text
    )

    mutated = text.replace(
        "github.event.context == 'Trusted PR Gate'",
        "github.event.context == 'Spoofed Gate'",
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_rejects_reciprocal_trusted_auto_workflow_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL]\n"
    assert current in text
    mutated = text.replace(
        current,
        "    workflows: ['CI — ƳƤ AI QA Automation Framework', CodeQL, 'Trusted PR Auto Gate — ƳƤ AI QA Automation Framework']\n",
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError, match="must remain accepted-main workflow_run/status/schedule only"
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_requires_automatic_gate_description(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-sync:\n")
    status_merge_start = text.index("\n  status-merge:\n", status_start)
    block = text[status_start:status_merge_start]
    current = (
        "      github.event.description == 'Automatic exact-subject trusted validation passed' &&\n"
    )
    assert current in block
    mutated_block = block.replace(current, "", 1)
    mutated = text[:status_start] + mutated_block + text[status_merge_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_rejects_floating_main_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-sync:\n")
    status_merge_start = text.index("\n  status-merge:\n", status_start)
    block = text[status_start:status_merge_start]
    current = "          ref: ${{ github.sha }}\n"
    assert current in block
    mutated_block = block.replace(
        current,
        "          ref: ${{ github.event.repository.default_branch }}\n",
        1,
    )
    mutated = text[:status_start] + mutated_block + text[status_merge_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="status synchronization must remain exact-revision-bound",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_exports_only_target_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = (
        "    outputs:\n"
        "      pr_number: ${{ steps.sync.outputs.pr_number }}\n"
        "      lane: ${{ steps.sync.outputs.lane }}\n"
    )
    assert current in text
    mutated = text.replace(
        current,
        current + "      head_sha: ${{ steps.sync.outputs.head_sha }}\n",
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="export only the exact dependency lane and PR number"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_requires_status_read_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-sync:\n")
    status_merge_start = text.index("\n  status-merge:\n", status_start)
    block = text[status_start:status_merge_start]
    current = "      statuses: read\n"
    assert current in block
    mutated_block = block.replace(current, "", 1)
    mutated = text[:status_start] + mutated_block + text[status_merge_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match=r"dependency-governance\.yml missing reviewed authority invariant",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_requires_pull_request_read_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-sync:\n")
    status_merge_start = text.index("\n  status-merge:\n", status_start)
    block = text[status_start:status_merge_start]
    current = "      pull-requests: read\n"
    assert current in block
    mutated_block = block.replace(current, "", 1)
    mutated = text[:status_start] + mutated_block + text[status_merge_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match=r"dependency-governance\.yml missing reviewed authority invariant",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_sync_cannot_gain_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-sync:\n")
    status_merge_start = text.index("\n  status-merge:\n", status_start)
    block = text[status_start:status_merge_start]
    current = "      contents: read\n"
    assert current in block
    mutated_block = block.replace(current, "      contents: write\n", 1)
    mutated = text[:status_start] + mutated_block + text[status_merge_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_requires_successful_sync_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = "      needs.status-sync.result == 'success' &&\n"
    assert current in text
    mutated = text.replace(current, "      github.event.state == 'success' &&\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_requires_nonempty_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = (
        "      needs.status-sync.outputs.pr_number != '' &&\n"
        "      needs.status-sync.outputs.lane != ''\n"
    )
    assert current in text
    mutated = text.replace(current, "      github.event.state == 'success'\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="missing reviewed authority invariant"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_routes_only_exact_dependency_lanes() -> None:
    text = (ROOT / ".github" / "workflows" / "dependency-governance.yml").read_text(
        encoding="utf-8"
    )
    status_start = text.index("  status-merge:\n")
    govern_start = text.index("\n  govern:\n", status_start)
    block = text[status_start:govern_start]

    assert 'case "$STATUS_DEPENDENCY_LANE" in' in block
    assert "            dependency-promotion)\n" in block
    assert "            dependabot-actions)\n" in block
    assert '--target-promotion-pr "$STATUS_DEPENDENCY_PR"' in block
    assert '--target-dependabot-pr "$STATUS_DEPENDENCY_PR"' in block
    assert "            *)\n              exit 1\n" in block


def test_dependency_governance_status_merge_rejects_floating_main_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-merge:\n")
    govern_start = text.index("\n  govern:\n", status_start)
    block = text[status_start:govern_start]
    current = "          ref: ${{ github.sha }}\n"
    assert current in block
    mutated_block = block.replace(
        current,
        "          ref: ${{ github.event.repository.default_branch }}\n",
        1,
    )
    mutated = text[:status_start] + mutated_block + text[govern_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="status-target merge must remain exact-revision-bound",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_cannot_gain_author_or_check_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    marker = (
        "    permissions:\n"
        "      actions: read\n"
        "      contents: write\n"
        "      pull-requests: write\n"
        "      statuses: read\n"
    )
    assert marker in text
    mutated = text.replace(
        marker,
        marker.replace(
            "      statuses: read\n",
            "      statuses: read\n      checks: write\n",
        ),
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="exact-subject, secret-free, and non-authoring"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_status_merge_cannot_regain_actions_write_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    status_start = text.index("  status-merge:\n")
    govern_start = text.index("\n  govern:\n", status_start)
    block = text[status_start:govern_start]
    current = "      actions: read\n"
    assert current in block
    mutated_block = block.replace(current, "      actions: write\n", 1)
    mutated = text[:status_start] + mutated_block + text[govern_start:]
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="exact-subject, secret-free, and non-authoring"):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_general_reconciler_rejects_status_reentry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = (
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n"
        "        startsWith(github.event.workflow_run.head_branch, "
        "'automation/dependency-promotion-')))\n"
    )
    assert current in text
    mutated = text.replace(
        current,
        current.replace(
            "      github.event_name == 'schedule' ||\n",
            "      github.event_name == 'schedule' || github.event_name == 'status' ||\n",
            1,
        ),
        1,
    )
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="restricted to schedule or reviewed same-repository dependency wakes",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_general_reconciler_rejects_fork_workflow_wake(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    current = (
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      (github.event_name == 'workflow_run' &&\n"
        "       github.event.workflow_run.head_repository.full_name == github.repository &&\n"
        "       (github.event.workflow_run.head_branch == 'main' ||\n"
        "        startsWith(github.event.workflow_run.head_branch, 'dependabot/') ||\n"
        "        startsWith(github.event.workflow_run.head_branch, "
        "'automation/dependency-promotion-')))\n"
    )
    assert current in text
    weakened = (
        "    if: >-\n"
        "      github.event_name == 'schedule' ||\n"
        "      github.event_name == 'workflow_run'\n"
    )
    mutated = text.replace(current, weakened, 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(
        ValueError,
        match="restricted to schedule or reviewed same-repository dependency wakes",
    ):
        ci_contract.verify_ci_contract(root)


def test_dependency_governance_rejects_status_authority_for_promotion_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "dependency-governance.yml"
    text = path.read_text(encoding="utf-8")
    marker = "          permission-pull-requests: write\n"
    assert marker in text
    mutated = text.replace(marker, marker + "          permission-statuses: write\n", 1)
    path.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(mutated),
    )

    with pytest.raises(ValueError, match="forbidden authority token"):
        ci_contract.verify_ci_contract(root)


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


def test_ci_contract_rejects_repository_dispatch_reintroduction(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  merge_group:\n"
    assert marker in text
    path.write_text(
        text.replace(
            marker,
            marker + "  repository_dispatch:\n    types: [trusted-pr-validation]\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_workflow_dispatch_in_ordinary_ci(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  merge_group:\n"
    assert marker in text
    path.write_text(text.replace(marker, marker + "  workflow_dispatch:\n", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_removing_reusable_ci_entrypoint(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    assert "  workflow_call:\n" in text
    path.write_text(text.replace("  workflow_call:\n", "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="trigger set must be exactly"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_trigger_expansion(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("on:\n", "on:\n  pull_request:\n", 1), encoding="utf-8")

    with pytest.raises(
        ValueError, match="must remain exact dependency/security-controller workflow_run only"
    ):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_cross_lane_security_merge_binding(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    security_binding = (
        "merge_source_re='^Merge pull request #[1-9][0-9]* from "
        "portyu9/automation/codeql-autoheal-'"
    )
    assert security_binding in text
    path.write_text(
        text.replace(
            security_binding,
            "merge_source_re='^Merge pull request #[1-9][0-9]* from "
            "portyu9/automation/dependency-promotion-'",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact governed-merge binding drifted"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_missing_main_advance_guard(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    guard = "      github.event.workflow_run.head_sha != github.sha\n"
    assert guard in text
    path.write_text(text.replace(guard, "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact governed-merge binding drifted"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_missing_control_parent_binding(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = ".parents[0].sha == $control"
    assert marker in text
    path.write_text(text.replace(marker, ".parents[0].sha != $control", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="exact governed-merge binding drifted"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_write_authority(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("  contents: read", "  contents: write", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="workflow permissions must be exactly contents: read"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_alternate_validation_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "    uses: ./.github/workflows/ci.yml"
    assert marker in text
    path.write_text(
        text.replace(marker, "    uses: ./.github/workflows/trusted-pr-auto.yml", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must call canonical reusable CI read-only"):
        ci_contract.verify_ci_contract(root)


def test_codeql_contract_rejects_removing_reusable_entrypoint(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "codeql.yml"
    text = path.read_text(encoding="utf-8")
    assert "  workflow_call:\n" in text
    path.write_text(text.replace("  workflow_call:\n", "", 1), encoding="utf-8")

    with pytest.raises(ValueError, match="trigger/input set differs"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_codeql_sarif_authority_expansion(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "      security-events: write"
    assert text.count(marker) == 1
    path.write_text(
        text.replace(marker, marker + "\n      statuses: write", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden authority token"):
        ci_contract.verify_ci_contract(root)


def test_post_merge_ci_rejects_alternate_codeql_workflow(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "post-merge-ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "    uses: ./.github/workflows/codeql.yml"
    assert marker in text
    path.write_text(
        text.replace(marker, "    uses: ./.github/workflows/trusted-pr-auto.yml", 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="isolate CodeQL SARIF authority"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_client_payload_subject_reintroduction(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  CI_SUBJECT_SHA: ${{ github.sha }}\n"
    replacement = (
        "  CI_SUBJECT_SHA: ${{ github.event_name == 'repository_dispatch' "
        "&& github.event.client_payload.expected_merge_sha || github.sha }}\n"
    )
    assert marker in text
    path.write_text(text.replace(marker, replacement, 1), encoding="utf-8")

    with pytest.raises(ValueError, match="environment/subject binding differs"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_write_permission(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8").replace("  contents: read", "  contents: write", 1)
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ValueError, match="workflow permissions must be exactly contents: read"):
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

    with pytest.raises(ValueError, match="forbidden authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_legacy_app_credential_in_ordinary_ci(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = '  PIP_DISABLE_PIP_VERSION_CHECK: "1"\n'
    assert marker in text
    path.write_text(
        text.replace(
            marker,
            marker + "  LEGACY_KEY: ${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}\n",
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden authority token"):
        ci_contract.verify_ci_contract(root)


def test_ci_contract_rejects_legacy_trusted_status_job_reintroduction(tmp_path: Path) -> None:
    root = _copy_workflows(tmp_path)
    path = root / ".github" / "workflows" / "ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "  required-gate:\n"
    assert marker in text
    path.write_text(
        text.replace(
            marker,
            "  trusted-status:\n"
            "    name: Trusted PR Gate Reporter\n"
            "    runs-on: ubuntu-24.04\n"
            "    steps:\n"
            "      - name: Forbidden legacy reporter\n"
            "        run: true\n\n" + marker,
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbidden authority token"):
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
        f"{ci_contract.EXPECTED_ACTION_SHAS['actions/upload-artifact']} # v7.0.1\n"
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
