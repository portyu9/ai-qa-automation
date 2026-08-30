from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

import scripts.auto_trusted_preflight as preflight

HEAD = "1" * 40
BASE = "2" * 40
MERGE = "3" * 40
BASE_TREE = "4" * 40
MERGE_TREE = "5" * 40
UNCHANGED = "6" * 40


class FakeAPI:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def get(self, path: str) -> Any:
        self.calls.append(path)
        try:
            return deepcopy(self.responses[path])
        except KeyError as exc:
            raise AssertionError(f"unexpected API path: {path}") from exc


def _tree(*, changed_path: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in preflight.PROTECTED_PATHS:
        sha = UNCHANGED
        if path == changed_path:
            sha = "7" * 40
        rows.append({"path": path, "sha": sha})
    return rows


def _responses(*, changed_path: str | None = None) -> dict[str, Any]:
    run_id = 42
    pr_number = 65
    live_run = {
        "id": run_id,
        "workflow_id": preflight.EXPECTED_WORKFLOW_ID,
        "name": preflight.EXPECTED_WORKFLOW_NAME,
        "path": preflight.EXPECTED_WORKFLOW_PATH,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "actor": {"login": preflight.EXPECTED_OWNER},
        "triggering_actor": {"login": preflight.EXPECTED_OWNER},
    }
    candidate = {
        "number": pr_number,
        "state": "open",
        "head": {
            "sha": HEAD,
            "repo": {"full_name": preflight.EXPECTED_REPOSITORY},
        },
        "base": {"ref": preflight.EXPECTED_DEFAULT_BRANCH},
    }
    pr = {
        **candidate,
        "draft": False,
        "base": {
            "ref": preflight.EXPECTED_DEFAULT_BRANCH,
            "sha": BASE,
        },
    }
    return {
        f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/{run_id}": live_run,
        f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/pulls?per_page=10": [candidate],
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main": {
            "object": {"sha": BASE}
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/{pr_number}": pr,
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/pull/{pr_number}/merge": {
            "object": {"sha": MERGE}
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{MERGE}": {
            "parents": [{"sha": BASE}, {"sha": HEAD}],
            "tree": {"sha": MERGE_TREE},
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{BASE}": {
            "tree": {"sha": BASE_TREE}
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{BASE_TREE}?recursive=1": {
            "truncated": False,
            "tree": _tree(),
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{MERGE_TREE}?recursive=1": {
            "truncated": False,
            "tree": _tree(changed_path=changed_path),
        },
    }


def _event() -> dict[str, Any]:
    return {"action": "completed", "workflow_run": {"id": 42, "head_sha": HEAD}}


def test_exact_live_subject_without_protected_changes_is_auto_eligible() -> None:
    admission = preflight.evaluate_admission(FakeAPI(_responses()), event=_event())

    assert admission.eligible is True
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.trusted_sha == BASE
    assert admission.protected_changes == ()


def test_protected_change_is_observed_but_not_auto_authorized() -> None:
    admission = preflight.evaluate_admission(
        FakeAPI(_responses(changed_path="tests")),
        event=_event(),
    )

    assert admission.eligible is False
    assert admission.protected_changes == (
        {
            "path": "tests",
            "base_oid": UNCHANGED,
            "subject_oid": "7" * 40,
        },
    )


def test_fork_head_is_rejected_before_pr_admission() -> None:
    responses = _responses()
    responses[
        f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"
    ]["head_repository"]["full_name"] = "attacker/fork"

    with pytest.raises(ValueError, match="fork/external-head"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_ambiguous_pull_request_resolution_fails_closed() -> None:
    responses = _responses()
    path = f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/pulls?per_page=10"
    responses[path].append(deepcopy(responses[path][0]))
    responses[path][1]["number"] = 66

    with pytest.raises(ValueError, match="exactly one"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_stale_base_relative_to_current_main_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main"][
        "object"
    ]["sha"] = "8" * 40

    with pytest.raises(ValueError, match="stale relative to current main"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("workflow_id", 999, "reviewed CI workflow"),
        ("path", ".github/workflows/rogue.yml", "name/path"),
        ("event", "push", "only accepts pull_request"),
        ("conclusion", "failure", "completed successful"),
    ],
)
def test_wrong_workflow_identity_or_result_fails_closed(
    field: str,
    value: object,
    message: str,
) -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"][field] = value

    with pytest.raises(ValueError, match=message):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_truncated_recursive_tree_fails_closed() -> None:
    responses = _responses()
    responses[
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{MERGE_TREE}?recursive=1"
    ]["truncated"] = True

    with pytest.raises(ValueError, match="truncated"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_merge_parent_order_must_bind_base_then_head() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{MERGE}"][
        "parents"
    ] = [{"sha": HEAD}, {"sha": BASE}]

    with pytest.raises(ValueError, match="parent order"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())
