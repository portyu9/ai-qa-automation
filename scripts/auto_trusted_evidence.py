from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

if __package__:
    from scripts import trusted_pr_evidence as evidence
    from scripts.trusted_pr_control import (
        PullRequestSubject,
        _mapping,
        _require_positive_int,
        _require_sha,
        resolve_current_subject,
    )
else:
    import trusted_pr_evidence as evidence
    from trusted_pr_control import (
        PullRequestSubject,
        _mapping,
        _require_positive_int,
        _require_sha,
        resolve_current_subject,
    )

EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_OWNER = "portyu9"
EXPECTED_WORKFLOW_ID = 339754724
EXPECTED_WORKFLOW_NAME = "CI — ƳƤ AI QA Automation Framework"
EXPECTED_WORKFLOW_PATH = ".github/workflows/ci.yml"
EXPECTED_WORKFLOW_EVENT = "pull_request"
EXPECTED_WORKFLOW_REF = "refs/heads/main"


def _require_automatic_context(expected_base_sha: str) -> None:
    if os.environ.get("GITHUB_EVENT_NAME") != "workflow_run":
        raise PermissionError("automatic protected evidence admission requires workflow_run")
    if os.environ.get("GITHUB_REF") != EXPECTED_WORKFLOW_REF:
        raise PermissionError("automatic protected evidence admission requires refs/heads/main")
    if os.environ.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise PermissionError("automatic protected evidence admission is repository-bound")
    if os.environ.get("GITHUB_REPOSITORY_OWNER") != EXPECTED_OWNER:
        raise PermissionError("automatic protected evidence admission is owner-bound")
    if os.environ.get("GITHUB_ACTOR") != EXPECTED_OWNER:
        raise PermissionError("automatic protected evidence admission requires the repository owner actor")
    if os.environ.get("GITHUB_SHA") != expected_base_sha:
        raise PermissionError("automatic protected evidence admission requires the exact trusted main revision")


def _require_exact_trigger_run(
    run: dict[str, Any],
    *,
    run_id: int,
    expected: PullRequestSubject,
    head_ref: str,
) -> None:
    if _require_positive_int(run.get("id"), label="workflow run ID") != run_id:
        raise ValueError("triggering workflow run identity drifted")
    if _require_positive_int(run.get("workflow_id"), label="workflow ID") != EXPECTED_WORKFLOW_ID:
        raise ValueError("triggering run is not the reviewed CI workflow")
    if run.get("name") != EXPECTED_WORKFLOW_NAME or run.get("path") != EXPECTED_WORKFLOW_PATH:
        raise ValueError("triggering workflow name/path differs from the reviewed CI workflow")
    if run.get("event") != EXPECTED_WORKFLOW_EVENT:
        raise ValueError("automatic protected evidence requires pull_request CI")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("triggering pull-request CI run must be completed successfully")
    if run.get("head_sha") != expected.head_sha or run.get("head_branch") != head_ref:
        raise ValueError("triggering run head identity differs from the admitted pull request")

    repository = _mapping(run.get("repository"), label="workflow repository")
    head_repository = _mapping(run.get("head_repository"), label="workflow head repository")
    if repository.get("full_name") != EXPECTED_REPOSITORY:
        raise ValueError("triggering run repository identity mismatch")
    if head_repository.get("full_name") != EXPECTED_REPOSITORY:
        raise ValueError("fork or external-head runs are not automatically authorized")
    actor = _mapping(run.get("actor"), label="workflow actor")
    triggering_actor = _mapping(run.get("triggering_actor"), label="workflow triggering actor")
    if actor.get("login") != EXPECTED_OWNER or triggering_actor.get("login") != EXPECTED_OWNER:
        raise ValueError("triggering CI must be owner-originated")
    if not evidence._run_matches(run, expected=expected, head_ref=head_ref):
        raise ValueError("triggering CI run is not bound to the exact live pull-request subject")


def verify_automatic_trusted_evidence(
    *,
    repository: str,
    token: str,
    expected: PullRequestSubject,
    protected_manifest_json: str,
    evidence_run_id: int,
) -> dict[str, Any]:
    _require_automatic_context(expected.base_sha)
    api = evidence.GitHubApi(repository=repository, token=token)

    resolve_current_subject(api, expected)
    current_pr = api.fetch_pull_request(expected.number)
    head_ref = evidence._pull_request_head_ref(current_pr, expected)
    protected_changes = evidence._verify_protected_manifest(
        api,
        expected,
        protected_manifest_json,
    )
    if not protected_changes:
        raise ValueError("automatic protected evidence admission requires a protected-path change")
    evidence._verify_candidate_workflow_binding(api, expected.merge_sha)

    run = _mapping(
        api.get_json(f"/repos/{api.repository}/actions/runs/{evidence_run_id}"),
        label="triggering workflow run",
    )
    _require_exact_trigger_run(
        run,
        run_id=evidence_run_id,
        expected=expected,
        head_ref=head_ref,
    )
    job_summary = evidence._verify_jobs(api, evidence_run_id)
    artifact_summary = evidence._verify_supply_chain_artifact(
        api,
        token=token,
        run_id=evidence_run_id,
        expected=expected,
        head_ref=head_ref,
    )

    merge_commit = api.fetch_git_commit(expected.merge_sha)
    merge_tree = _mapping(merge_commit.get("tree"), label="prospective merge tree")
    merge_tree_sha = _require_sha(merge_tree.get("sha"), label="prospective merge tree SHA")
    if artifact_summary["build_manifest_source_tree"] != merge_tree_sha:
        raise ValueError("persisted build manifest tree does not match the live prospective merge tree")

    # Re-resolve immediately before returning authority-bearing evidence. A head/base/merge
    # change after the originating run must invalidate the entire admission attempt.
    resolve_current_subject(api, expected)

    target_url = run.get("html_url")
    expected_url = f"https://github.com/{repository}/actions/runs/{evidence_run_id}"
    if target_url != expected_url:
        raise ValueError("triggering workflow evidence target URL is not canonical")

    return {
        "result": "SUCCESS",
        "authorization_mode": "automatic-default-branch-owner-origin",
        "subject": {
            "pr_number": expected.number,
            "head_sha": expected.head_sha,
            "base_sha": expected.base_sha,
            "merge_sha": expected.merge_sha,
        },
        "protected_changes": protected_changes,
        "evidence_run_id": evidence_run_id,
        "evidence_target_url": expected_url,
        "jobs": job_summary,
        "supply_chain_artifact": artifact_summary,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automatically admit exact successful pull-request CI evidence for protected changes"
    )
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    parser.add_argument("--expected-merge-sha", required=True)
    parser.add_argument("--protected-manifest-json", required=True)
    parser.add_argument("--evidence-run-id", required=True)
    parser.add_argument("--github-output")
    return parser


def main() -> None:
    args = _parser().parse_args()
    expected = PullRequestSubject(
        number=_require_positive_int(args.pr_number, label="pull-request number"),
        head_sha=_require_sha(args.expected_head_sha, label="expected head SHA"),
        base_sha=_require_sha(args.expected_base_sha, label="expected base SHA"),
        merge_sha=_require_sha(args.expected_merge_sha, label="expected merge SHA"),
    )
    result = verify_automatic_trusted_evidence(
        repository=os.environ.get("GITHUB_REPOSITORY", ""),
        token=os.environ.get("GITHUB_TOKEN", ""),
        expected=expected,
        protected_manifest_json=args.protected_manifest_json,
        evidence_run_id=_require_positive_int(args.evidence_run_id, label="evidence workflow run ID"),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.github_output:
        output = Path(args.github_output)
        if output.is_symlink():
            raise ValueError("GITHUB_OUTPUT must not be a symlink")
        with output.open("a", encoding="utf-8") as handle:
            handle.write(f"evidence_run_id={result['evidence_run_id']}\n")
            handle.write(f"evidence_target_url={result['evidence_target_url']}\n")


if __name__ == "__main__":
    main()
