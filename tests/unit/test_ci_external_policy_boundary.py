from pathlib import Path

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def test_ci_contract_reports_independent_status_publisher_boundary() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    ordinary = result["workflows"]["automatic"]
    trusted_auto = result["workflows"]["trusted_auto"]
    limitations = "\n".join(result["limitations"])

    assert ordinary["status_write_authority"] == "none"
    assert ordinary["protected_maintenance_authority"] == "external-trusted-gate-only"
    assert trusted_auto["status_writer"] == "dedicated-github-app"
    assert trusted_auto["maintenance_authority"] == (
        "independent-external-one-shot-exact-subject-gate"
    )
    assert "automatic read-only development evidence" in limitations
    assert "independently deployed external Trusted PR Gate" in limitations
    assert "repository_dispatch is not a maintenance authority" in limitations
    assert "trusted-pr-gate Environment/App credential remains required" in limitations
    assert "protected-branch enforcement must remain strict/up-to-date" in limitations
