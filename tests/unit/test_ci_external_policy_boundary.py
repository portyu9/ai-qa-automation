from pathlib import Path

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def test_ci_contract_reports_default_branch_definition_only_external_policy_boundary() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    automatic = result["workflows"]["automatic"]
    limitations = "\n".join(result["limitations"])

    assert automatic["external_policy_required"] is True
    assert (
        automatic["external_policy_invariant"]
        == "default-branch-definition-only-for-protected-identity"
    )
    assert "Denying pull_request alone is insufficient." in limitations
    assert "default-branch-definition-only external Actions Policy invariant" in limitations
