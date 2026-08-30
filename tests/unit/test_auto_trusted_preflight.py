from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
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
        "base": {
            "ref": preflight.EXPECTED_DEFAULT_BRANCH,
            "repo": {"full_name": preflight.EXPECTED_REPOSITORY},
        },
    }
    pr = {
        **candidate,
        "draft": False,
        "base": {
            "ref": preflight.EXPECTED_DEFAULT_BRANCH,
            "sha": BASE,
            "repo": {"full_name": preflight.EXPECTED_REPOSITORY},
        },
    }
    return {
        f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/{run_id}": live_run,
        (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/pulls"
            f"?per_page={preflight.MAX_PULL_REQUEST_CANDIDATES}"
        ): [candidate],
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main": {
            "ref": "refs/heads/main",
            "object": {"sha": BASE, "type": "commit"},
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/{pr_number}": pr,
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/pull/{pr_number}/merge": {
            "ref": f"refs/pull/{pr_number}/merge",
            "object": {"sha": MERGE, "type": "commit"},
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{MERGE}": {
            "sha": MERGE,
            "parents": [{"sha": BASE}, {"sha": HEAD}],
            "tree": {"sha": MERGE_TREE},
        },
        f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{BASE}": {
            "sha": BASE,
            "tree": {"sha": BASE_TREE},
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


def _pulls_path() -> str:
    return (
        f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/pulls"
        f"?per_page={preflight.MAX_PULL_REQUEST_CANDIDATES}"
    )


def test_exact_live_subject_without_protected_changes_is_auto_eligible() -> None:
    admission = preflight.evaluate_admission(FakeAPI(_responses()), event=_event())

    assert admission.eligible is True
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.trusted_sha == BASE
    assert admission.protected_changes == ()


@pytest.mark.parametrize("changed_path", ["tests", ".gitattributes"])
def test_protected_change_is_observed_but_not_auto_authorized(changed_path: str) -> None:
    admission = preflight.evaluate_admission(
        FakeAPI(_responses(changed_path=changed_path)),
        event=_event(),
    )

    assert admission.eligible is False
    assert admission.protected_changes == (
        {
            "path": changed_path,
            "base_oid": UNCHANGED,
            "subject_oid": "7" * 40,
        },
    )


def test_fork_head_is_rejected_before_pr_admission() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["head_repository"][
        "full_name"
    ] = "attacker/fork"

    with pytest.raises(ValueError, match="fork/external-head"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_ambiguous_pull_request_resolution_fails_closed() -> None:
    responses = _responses()
    responses[_pulls_path()].append(deepcopy(responses[_pulls_path()][0]))
    responses[_pulls_path()][1]["number"] = 66

    with pytest.raises(ValueError, match="exactly one"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_saturated_pull_request_page_fails_closed() -> None:
    responses = _responses()
    candidate = responses[_pulls_path()][0]
    responses[_pulls_path()] = [
        deepcopy(candidate) for _ in range(preflight.MAX_PULL_REQUEST_CANDIDATES)
    ]

    with pytest.raises(ValueError, match="pagination limit"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_stale_base_relative_to_current_main_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main"]["object"]["sha"] = (
        "8" * 40
    )

    with pytest.raises(ValueError, match="stale relative to current main"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_wrong_base_repository_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["base"]["repo"]["full_name"] = (
        "attacker/other"
    )

    with pytest.raises(ValueError, match="expected repository main branch"):
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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("ref", "refs/heads/release", "identify exactly"),
        ("type", "tag", "point to a commit"),
    ],
)
def test_main_ref_identity_and_type_fail_closed(field: str, value: str, message: str) -> None:
    responses = _responses()
    main_ref = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main"]
    if field == "ref":
        main_ref["ref"] = value
    else:
        main_ref["object"][field] = value

    with pytest.raises(ValueError, match=message):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("ref", "refs/pull/65/head", "identify exactly"),
        ("type", "tag", "point to a commit"),
    ],
)
def test_merge_ref_identity_and_type_fail_closed(field: str, value: str, message: str) -> None:
    responses = _responses()
    merge_ref = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/pull/65/merge"]
    if field == "ref":
        merge_ref["ref"] = value
    else:
        merge_ref["object"][field] = value

    with pytest.raises(ValueError, match=message):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_merge_commit_identity_mismatch_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{MERGE}"]["sha"] = "8" * 40

    with pytest.raises(ValueError, match="identity drifted"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_base_commit_identity_mismatch_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{BASE}"]["sha"] = "8" * 40

    with pytest.raises(ValueError, match="identity drifted"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_truncated_recursive_tree_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/trees/{MERGE_TREE}?recursive=1"][
        "truncated"
    ] = True

    with pytest.raises(ValueError, match="truncated"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_merge_parent_order_must_bind_base_then_head() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/commits/{MERGE}"]["parents"] = [
        {"sha": HEAD},
        {"sha": BASE},
    ]

    with pytest.raises(ValueError, match="parent order"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_event_file_ingestion_rejects_symlink(tmp_path: Path) -> None:
    source = tmp_path / "event-source.json"
    source.write_text(json.dumps(_event()), encoding="utf-8")
    link = tmp_path / "event.json"
    link.symlink_to(source)

    with pytest.raises(ValueError, match="cannot be opened"):
        preflight._read_json_file(link, max_bytes=preflight.MAX_EVENT_BYTES, label="workflow event")


def test_api_path_rejects_traversal_before_network() -> None:
    api = preflight.GitHubAPI(
        api_url="https://api.github.com",
        token="token",
        repository=preflight.EXPECTED_REPOSITORY,
    )

    with pytest.raises(ValueError, match="fixed-repository path"):
        api.get("/repos/portyu9/ai-qa-automation/../other")
