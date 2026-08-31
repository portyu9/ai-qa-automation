from __future__ import annotations

from typing import Any

import pytest

import scripts.auto_trusted_evidence as automatic
from scripts.trusted_pr_control import PullRequestSubject

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def _expected() -> PullRequestSubject:
    return PullRequestSubject(number=70, head_sha=SHA_A, base_sha=SHA_B, merge_sha=SHA_C)


def _run() -> dict[str, Any]:
    return {
        "id": 123,
        "workflow_id": automatic.EXPECTED_WORKFLOW_ID,
        "name": automatic.EXPECTED_WORKFLOW_NAME,
        "path": automatic.EXPECTED_WORKFLOW_PATH,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SHA_A,
        "head_branch": "feature",
        "repository": {"full_name": automatic.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": automatic.EXPECTED_REPOSITORY},
        "actor": {"login": automatic.EXPECTED_OWNER},
        "triggering_actor": {"login": automatic.EXPECTED_OWNER},
        "pull_requests": [
            {
                "number": 70,
                "head": {"sha": SHA_A, "ref": "feature"},
                "base": {"sha": SHA_B, "ref": "main"},
            }
        ],
    }


def _set_valid_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_run")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_REPOSITORY", automatic.EXPECTED_REPOSITORY)
    monkeypatch.setenv("GITHUB_REPOSITORY_OWNER", automatic.EXPECTED_OWNER)
    monkeypatch.setenv("GITHUB_ACTOR", automatic.EXPECTED_OWNER)
    monkeypatch.setenv("GITHUB_SHA", SHA_B)


def test_automatic_context_requires_default_branch_owner_workflow_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_valid_context(monkeypatch)
    automatic._require_automatic_context(SHA_B)

    for key, value, match in (
        ("GITHUB_EVENT_NAME", "repository_dispatch", "requires workflow_run"),
        ("GITHUB_REF", "refs/heads/feature", "requires refs/heads/main"),
        ("GITHUB_ACTOR", "github-actions[bot]", "requires the repository owner actor"),
        ("GITHUB_SHA", SHA_C, "exact trusted main revision"),
    ):
        _set_valid_context(monkeypatch)
        monkeypatch.setenv(key, value)
        with pytest.raises(PermissionError, match=match):
            automatic._require_automatic_context(SHA_B)


def test_trigger_run_requires_exact_reviewed_ci_and_owner_origin() -> None:
    automatic._require_exact_trigger_run(
        _run(),
        run_id=123,
        expected=_expected(),
        head_ref="feature",
    )

    mutations = (
        ({"workflow_id": 999}, "reviewed CI workflow"),
        ({"path": ".github/workflows/other.yml"}, "name/path"),
        ({"event": "push"}, "pull_request CI"),
        ({"conclusion": "failure"}, "completed successfully"),
        ({"head_sha": SHA_C}, "head identity"),
        ({"head_repository": {"full_name": "attacker/fork"}}, "external-head"),
        ({"actor": {"login": "someone-else"}}, "owner-originated"),
        ({"triggering_actor": {"login": "someone-else"}}, "owner-originated"),
    )
    for patch, match in mutations:
        with pytest.raises(ValueError, match=match):
            automatic._require_exact_trigger_run(
                _run() | patch,
                run_id=123,
                expected=_expected(),
                head_ref="feature",
            )


def test_trigger_run_rejects_wrong_pull_request_binding() -> None:
    run = _run()
    run["pull_requests"] = [
        {
            "number": 70,
            "head": {"sha": SHA_A, "ref": "feature"},
            "base": {"sha": SHA_C, "ref": "main"},
        }
    ]
    with pytest.raises(ValueError, match="exact live pull-request subject"):
        automatic._require_exact_trigger_run(
            run,
            run_id=123,
            expected=_expected(),
            head_ref="feature",
        )
