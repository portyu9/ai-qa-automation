from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

import pytest

import scripts.trusted_pr_evidence as evidence
import scripts.verify_ci_contract as ci_contract
from scripts.trusted_pr_control import PullRequestSubject

ROOT = Path(__file__).resolve().parents[2]
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
SHA_D = "d" * 40


def _manifest_item(path: str = ".github") -> dict[str, str]:
    return {"path": path, "base_oid": SHA_A, "subject_oid": SHA_B}


def test_trusted_evidence_contract_is_exact_and_candidate_nonexecuting() -> None:
    result = ci_contract.verify_ci_contract(ROOT)["workflows"]["trusted_evidence"]

    assert result["workflow_definition"] == "exact-reviewed-git-blob"
    assert result["evidence_verifier"] == "exact-reviewed-git-blob"
    assert result["candidate_execution"] == "none"

    text = (ROOT / ".github" / "workflows" / "trusted-pr-evidence.yml").read_text(
        encoding="utf-8"
    )
    assert text.count("ref: ${{ github.sha }}") == 2
    assert "ref: ${{ github.event.client_payload.expected_merge_sha }}" not in text


def test_manifest_parser_rejects_unknown_duplicate_and_malformed_authority() -> None:
    with pytest.raises(ValueError, match="unknown or duplicate"):
        evidence._parse_manifest('[{"path":"docs","base_oid":"' + SHA_A + '","subject_oid":"' + SHA_B + '"}]')

    duplicate = [_manifest_item(), _manifest_item()]
    with pytest.raises(ValueError, match="unknown or duplicate"):
        evidence._parse_manifest(__import__("json").dumps(duplicate))

    malformed = [_manifest_item() | {"base_oid": "short"}]
    with pytest.raises(ValueError, match="full Git object ID"):
        evidence._parse_manifest(__import__("json").dumps(malformed))


def test_run_match_requires_exact_pr_head_base_and_branch() -> None:
    expected = PullRequestSubject(number=70, head_sha=SHA_A, base_sha=SHA_B, merge_sha=SHA_C)
    run: dict[str, Any] = {
        "event": "pull_request",
        "path": ".github/workflows/ci.yml",
        "head_sha": SHA_A,
        "head_branch": "feature",
        "status": "completed",
        "conclusion": "success",
        "pull_requests": [
            {
                "number": 70,
                "head": {"sha": SHA_A, "ref": "feature"},
                "base": {"sha": SHA_B, "ref": "main"},
            }
        ],
    }

    assert evidence._run_matches(run, expected=expected, head_ref="feature")
    assert not evidence._run_matches(run | {"head_sha": SHA_D}, expected=expected, head_ref="feature")
    wrong_base = dict(run)
    wrong_base["pull_requests"] = [
        {
            "number": 70,
            "head": {"sha": SHA_A, "ref": "feature"},
            "base": {"sha": SHA_D, "ref": "main"},
        }
    ]
    assert not evidence._run_matches(wrong_base, expected=expected, head_ref="feature")


class _JobsApi:
    repository = "owner/repo"

    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs

    def get_json(self, path: str) -> dict[str, Any]:
        assert path.endswith("/jobs?per_page=100&filter=latest")
        return {"total_count": len(self.jobs), "jobs": self.jobs}


def _successful_job(name: str, *, steps: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"name": name, "conclusion": "success", "steps": steps or []}


def _successful_jobs() -> list[dict[str, Any]]:
    return [
        _successful_job(
            "Supply Chain / Wheel + SBOM + Container",
            steps=[{"name": "Verify CI authority contract", "conclusion": "success"}],
        ),
        _successful_job("Quality / Python 3.11.16"),
        _successful_job("Quality / Python 3.14.7"),
        _successful_job("Security Gates"),
        _successful_job("Playwright Reference SUT"),
        _successful_job("34-Case Deterministic Control Evaluation"),
        _successful_job(
            "Required PR Gate",
            steps=[{"name": "Require every automatic gate to succeed", "conclusion": "success"}],
        ),
        {"name": "Trusted PR Gate Reporter", "conclusion": "skipped", "steps": []},
    ]


def test_job_admission_requires_candidate_ci_contract_and_required_gate() -> None:
    result = evidence._verify_jobs(_JobsApi(_successful_jobs()), 123)
    assert result["quality_jobs"] == ["Quality / Python 3.11.16", "Quality / Python 3.14.7"]

    jobs = _successful_jobs()
    jobs[0] = _successful_job("Supply Chain / Wheel + SBOM + Container")
    with pytest.raises(ValueError, match="CI authority contract"):
        evidence._verify_jobs(_JobsApi(jobs), 123)

    jobs = _successful_jobs()
    jobs[6] = _successful_job("Required PR Gate")
    with pytest.raises(ValueError, match="deterministically aggregate"):
        evidence._verify_jobs(_JobsApi(jobs), 123)


class _WorkflowApi:
    repository = "owner/repo"

    def __init__(self, text: str) -> None:
        self.text = text

    def get_json(self, path: str) -> dict[str, Any]:
        assert path.startswith("/repos/owner/repo/contents/.github/workflows/ci.yml?ref=")
        return {
            "encoding": "base64",
            "content": base64.b64encode(self.text.encode("utf-8")).decode("ascii"),
        }


def test_candidate_workflow_binding_rejects_wrong_subject_or_missing_aggregate() -> None:
    valid = (
        "on:\n  pull_request:\n"
        "env:\n  "
        + evidence.EXPECTED_SUBJECT_BINDING
        + "\njobs:\n  required-gate:\n    name: Required PR Gate\n"
    )
    evidence._verify_candidate_workflow_binding(_WorkflowApi(valid), SHA_C)

    with pytest.raises(ValueError, match="bound to github.sha"):
        evidence._verify_candidate_workflow_binding(
            _WorkflowApi(valid.replace(evidence.EXPECTED_SUBJECT_BINDING, "CI_SUBJECT_SHA: deadbeef")),
            SHA_C,
        )

    with pytest.raises(ValueError, match="Required PR Gate"):
        evidence._verify_candidate_workflow_binding(
            _WorkflowApi(valid.replace("    name: Required PR Gate\n", "")),
            SHA_C,
        )
