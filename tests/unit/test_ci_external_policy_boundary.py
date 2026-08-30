from pathlib import Path

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]


def test_ci_contract_reports_independent_status_publisher_boundary() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    automatic = result["workflows"]["automatic"]
    limitations = "\n".join(result["limitations"])

    assert automatic["external_policy_required"] is True
    assert automatic["external_policy_invariant"] == (
        "pull-request-feedback-plus-owner-dispatch"
    )
    assert automatic["external_policy_capability"] == (
        "main-only-environment-and-required-status-app-binding"
    )
    assert automatic["merge_enforcement_invariant"] == "strict-up-to-date-required-status"
    assert automatic["reporter_identity"] == "dedicated-github-app-installation-token"
    assert "Ordinary pull_request execution is automatic development evidence" in limitations
    assert "separately installed GitHub App" in limitations
    assert "main-only trusted-pr-gate environment" in limitations
    assert "explicit trust transition" in limitations
    assert "protected-branch enforcement must remain strict/up-to-date" in limitations
