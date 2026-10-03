from __future__ import annotations

from pathlib import Path

import pytest

import scripts.verify_ci_contract as ci_contract
import scripts.verify_fork_cloud_authority as fork_authority

ROOT = Path(__file__).resolve().parents[2]
RECONCILER = ROOT / ".github" / "workflows" / "ruleset-reconciler.yml"
SENTINEL = ROOT / ".github" / "workflows" / "ruleset-drift-sentinel.yml"


def _accept_mutated_reconciler_structure(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_RULESET_RECONCILER_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(text),
    )


def _accept_mutated_sentinel_structure(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    monkeypatch.setattr(
        ci_contract,
        "EXPECTED_RULESET_DRIFT_SENTINEL_WORKFLOW_BLOB_SHA",
        ci_contract._workflow_structure_sha1(text),
    )


def test_ruleset_workflows_match_frozen_authority_contract() -> None:
    reconciler = RECONCILER.read_text(encoding="utf-8")
    sentinel = SENTINEL.read_text(encoding="utf-8")

    assert (
        ci_contract._verify_ruleset_reconciler_workflow(reconciler)["transition"]
        == "exact-predecessor-to-exact-successor-one-put"
    )
    assert ci_contract._verify_ruleset_drift_sentinel_workflow(sentinel)["mutation"] == "forbidden"
    assert (
        fork_authority._verify_workflow_text("ruleset-reconciler.yml", reconciler)[
            "aws_authentication"
        ]
        == "forbidden"
    )
    assert (
        fork_authority._verify_workflow_text("ruleset-drift-sentinel.yml", sentinel)["secrets"]
        == {}
    )


def test_ruleset_reconciler_rejects_exact_classification_in_read_only_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    current = "classify-observable --live live-plan.json"
    assert text.count(current) == 1
    mutated = text.replace(current, "classify --live live-plan.json", 1)
    _accept_mutated_reconciler_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="observable classification"):
        ci_contract._verify_ruleset_reconciler_workflow(mutated)


def test_ruleset_reconciler_rejects_second_ruleset_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    marker = '          GH_TOKEN="$admin_token" gh api --method PUT \\\n'
    assert text.count(marker) == 1
    mutated = text.replace(marker, marker + marker, 1)
    _accept_mutated_reconciler_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="exactly one administration PUT"):
        ci_contract._verify_ruleset_reconciler_workflow(mutated)


def test_ruleset_reconciler_rejects_admin_secret_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    current = "${{ secrets.PORTYU9_RULESET_ADMIN_PRIVATE_KEY }}"
    assert text.count(current) == 1
    mutated = text.replace(
        current,
        "${{ secrets.TRUSTED_GATE_APP_PRIVATE_KEY }}",
        1,
    )
    _accept_mutated_reconciler_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="secret inventory drifted"):
        ci_contract._verify_ruleset_reconciler_workflow(mutated)


def test_ruleset_reconciler_rejects_duplicate_admin_secret_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    marker = "          ADMIN_APP_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_APP_ID }}\n"
    assert text.count(marker) == 1
    mutated = text.replace(
        marker,
        marker + "          DUPLICATE_ADMIN_APP_ID: ${{ secrets.PORTYU9_RULESET_ADMIN_APP_ID }}\n",
        1,
    )
    _accept_mutated_reconciler_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="secret inventory drifted"):
        ci_contract._verify_ruleset_reconciler_workflow(mutated)


def test_ruleset_reconciler_rejects_oidc_or_native_write_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    marker = "permissions:\n  contents: read\n"
    assert text.count(marker) == 1
    mutated = text.replace(marker, marker + "  id-token: write\n", 1)
    _accept_mutated_reconciler_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match=r"top-level token|forbidden authority"):
        ci_contract._verify_ruleset_reconciler_workflow(mutated)


def test_ruleset_drift_sentinel_rejects_unreviewed_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = "        env:\n"
    assert text.count(marker) == 1
    mutated = text.replace(
        marker,
        marker + "          BAD_SECRET: ${{ secrets.BAD_SECRET }}\n",
        1,
    )
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="secret-free"):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_ruleset_drift_sentinel_rejects_native_write_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = "permissions:\n  contents: read\n"
    assert text.count(marker) == 1
    mutated = text.replace(marker, marker + "  id-token: write\n", 1)
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match=r"native token|forbidden authority"):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_ruleset_drift_sentinel_rejects_repository_mutation_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = (
        '          GH_TOKEN="$GITHUB_TOKEN" gh api '
        "repos/portyu9/ai-qa-automation/rulesets/21201916 "
        '> "$RUNNER_TEMP/live-ruleset.json"\n'
    )
    assert text.count(marker) == 1
    mutation = (
        '          GH_TOKEN="$GITHUB_TOKEN" gh api '
        '--method PATCH repos/portyu9/ai-qa-automation/rulesets/21201916 '
        '> "$RUNNER_TEMP/forbidden.json"\n'
    )
    mutated = text.replace(marker, mutation + marker, 1)
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(
        ValueError, match=r"forbidden repository mutation API form|forbidden authority"
    ):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_ruleset_drift_sentinel_rejects_unreviewed_api_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = (
        '          GH_TOKEN="$GITHUB_TOKEN" gh api '
        "repos/portyu9/ai-qa-automation/rulesets/21201916 "
        '> "$RUNNER_TEMP/live-ruleset.json"\n'
    )
    assert text.count(marker) == 1
    extra = (
        '          GH_TOKEN="$GITHUB_TOKEN" gh api '
        "repos/portyu9/ai-qa-automation/rulesets/21201916 "
        "--jq .enforcement > /dev/null\n"
    )
    mutated = text.replace(marker, extra + marker, 1)
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="API call inventory drifted"):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_ruleset_drift_sentinel_rejects_privileged_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = "    timeout-minutes: 4\n"
    assert text.count(marker) == 1
    mutated = text.replace(marker, marker + "    environment: ruleset-admin-identity\n", 1)
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="forbidden authority"):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_ruleset_drift_sentinel_requires_revision_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    current = "require-witnessed-successor"
    assert text.count(current) == 1
    mutated = text.replace(current, "classify-observable", 1)
    _accept_mutated_sentinel_structure(monkeypatch, mutated)

    with pytest.raises(ValueError, match="missing reviewed fragment"):
        ci_contract._verify_ruleset_drift_sentinel_workflow(mutated)


def test_fork_authority_rejects_sentinel_secret() -> None:
    text = SENTINEL.read_text(encoding="utf-8")
    marker = "          GITHUB_TOKEN: ${{ github.token }}\n"
    assert text.count(marker) == 1
    mutated = text.replace(
        marker,
        marker + "          BAD_SECRET: ${{ secrets.BAD_SECRET }}\n",
        1,
    )

    with pytest.raises(ValueError, match="secret references differ from reviewed allowlist"):
        fork_authority._verify_workflow_text("ruleset-drift-sentinel.yml", mutated)


def test_fork_authority_rejects_second_ruleset_admin_secret() -> None:
    text = RECONCILER.read_text(encoding="utf-8")
    marker = "          ADMIN_PRIVATE_KEY: ${{ secrets.PORTYU9_RULESET_ADMIN_PRIVATE_KEY }}\n"
    assert text.count(marker) == 1
    mutated = text.replace(
        marker,
        marker + "          SECOND_ADMIN_SECRET: ${{ secrets.SECOND_ADMIN_SECRET }}\n",
        1,
    )

    with pytest.raises(ValueError, match="secret references differ from reviewed allowlist"):
        fork_authority._verify_workflow_text("ruleset-reconciler.yml", mutated)
