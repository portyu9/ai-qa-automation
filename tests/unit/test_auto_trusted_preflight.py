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


class ScheduledFakeAPI(FakeAPI):
    def __init__(self, responses: dict[str, Any], pulls: list[dict[str, Any]]) -> None:
        super().__init__(responses)
        self.pulls = pulls
        self.list_calls: list[tuple[str, int]] = []

    def list_all(
        self, path: str, *, max_pages: int = preflight.MAX_API_PAGES
    ) -> list[dict[str, Any]]:
        self.list_calls.append((path, max_pages))
        expected = (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls"
            f"?state=open&base={preflight.EXPECTED_DEFAULT_BRANCH}"
        )
        if path != expected or max_pages != 1:
            raise AssertionError(f"unexpected scheduled list path: {path} max_pages={max_pages}")
        return deepcopy(self.pulls)


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
        "run_attempt": 1,
        "workflow_id": preflight.EXPECTED_CI_WORKFLOW_ID,
        "name": preflight.EXPECTED_CI_WORKFLOW_NAME,
        "path": preflight.EXPECTED_CI_WORKFLOW_PATH,
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "head_sha": HEAD,
        "repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "head_repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "actor": {"login": preflight.EXPECTED_OWNER, "id": preflight.EXPECTED_OWNER_ID},
        "triggering_actor": {
            "login": preflight.EXPECTED_OWNER,
            "id": preflight.EXPECTED_OWNER_ID,
        },
    }
    candidate = {
        "number": pr_number,
        "state": "open",
        "head": {
            "ref": "fix/trusted-owner-routine",
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
        "mergeable": True,
        "user": {"login": preflight.EXPECTED_OWNER, "id": preflight.EXPECTED_OWNER_ID},
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
    assert admission.lane == "owner-routine"
    assert admission.qualification_ready is True
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.trusted_sha == BASE
    assert admission.protected_changes == ()


def test_repository_control_plane_is_never_routine_auto_eligible() -> None:
    assert {".github", "scripts"} <= set(preflight.PROTECTED_PATHS)
    assert "tests" not in preflight.PROTECTED_PATHS


@pytest.mark.parametrize(
    "changed_path",
    ["requirements", ".gitattributes", ".github", "scripts"],
)
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


def test_scheduled_bot_reconciliation_selects_security_lane_from_fresh_pr() -> None:
    responses = _responses()
    live = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    live["user"] = {
        "login": preflight.GITHUB_ACTIONS_LOGIN,
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    live["head"]["ref"] = "automation/codeql-autoheal-7-abcdef123456"
    summary = deepcopy(live)
    api = ScheduledFakeAPI(responses, [summary])

    admission = preflight.evaluate_admission(api, event={}, event_name="schedule")

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == "security-autoheal"
    assert admission.pr_number == 65
    assert admission.head_ref == "automation/codeql-autoheal-7-abcdef123456"
    assert api.calls.count(f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65") == 2


def test_scheduled_bot_reconciliation_skips_nonmergeable_higher_priority_candidate() -> None:
    responses = _responses()
    security = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    security["number"] = 65
    security["user"] = {
        "login": preflight.GITHUB_ACTIONS_LOGIN,
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    security["head"]["ref"] = "automation/codeql-autoheal-7-abcdef123456"
    security["mergeable"] = False

    action = deepcopy(security)
    action["number"] = 66
    action["user"] = {
        "login": preflight.DEPENDABOT_LOGIN,
        "id": preflight.DEPENDABOT_USER_ID,
    }
    action["head"]["ref"] = "dependabot/github_actions/actions/checkout-7"
    action["mergeable"] = True
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/66"] = action
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/pull/66/merge"] = {
        "ref": "refs/pull/66/merge",
        "object": {"sha": MERGE, "type": "commit"},
    }

    api = ScheduledFakeAPI(responses, [deepcopy(security), deepcopy(action)])
    admission = preflight.evaluate_admission(api, event={}, event_name="schedule")

    assert admission is not None
    assert admission.lane == "dependabot-actions"
    assert admission.pr_number == 66


def test_fork_head_is_rejected_before_pr_admission() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["head_repository"][
        "full_name"
    ] = "attacker/fork"

    with pytest.raises(ValueError, match="repository identity mismatch"):
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


@pytest.mark.parametrize("mergeable", [False, None])
def test_indefinite_or_conflicting_mergeability_fails_closed(mergeable: bool | None) -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["mergeable"] = mergeable

    with pytest.raises(ValueError, match="definitively mergeable"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_wrong_base_repository_fails_closed() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["base"]["repo"]["full_name"] = (
        "attacker/other"
    )

    with pytest.raises(ValueError, match="expected repository main branch"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workflow_id", 999),
        ("path", ".github/workflows/rogue.yml"),
        ("event", "push"),
        ("conclusion", "failure"),
    ],
)
def test_unreviewed_or_unsuccessful_workflow_wake_is_ignored(
    field: str,
    value: object,
) -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"][field] = value

    assert preflight.evaluate_admission(FakeAPI(responses), event=_event()) is None


@pytest.mark.parametrize(
    ("user", "branch", "expected_lane"),
    [
        (
            {"login": preflight.DEPENDABOT_LOGIN, "id": preflight.DEPENDABOT_USER_ID},
            "dependabot/github_actions/actions/checkout-7",
            "dependabot-actions",
        ),
        (
            {"login": preflight.GITHUB_ACTIONS_LOGIN, "id": preflight.GITHUB_ACTIONS_USER_ID},
            "automation/dependency-promotion-171-abcdef123456",
            "dependency-promotion",
        ),
        (
            {"login": preflight.GITHUB_ACTIONS_LOGIN, "id": preflight.GITHUB_ACTIONS_USER_ID},
            "automation/codeql-autoheal-7-abcdef123456",
            "security-autoheal",
        ),
    ],
)
def test_governed_bot_lane_requires_exact_identity_and_branch_grammar(
    user: dict[str, object],
    branch: str,
    expected_lane: str,
) -> None:
    pr = {"user": user, "head": {"ref": branch}}
    assert preflight._bot_lane(pr) == expected_lane


@pytest.mark.parametrize(
    "branch",
    [
        "dependabot/github_actions/actions/checkout-7",
        "automation/dependency-promotion-171-abcdef123456",
        "automation/codeql-autoheal-7-abcdef123456",
    ],
)
def test_advanced_security_reporting_actor_has_no_governed_lane(branch: str) -> None:
    pr = {
        "user": {
            "login": "github-advanced-security[bot]",
            "id": preflight.GITHUB_ACTIONS_USER_ID,
        },
        "head": {"ref": branch},
    }

    assert preflight._bot_lane(pr) is None


def test_governed_bot_lane_rejects_lookalike_identity() -> None:
    pr = {
        "user": {"login": preflight.GITHUB_ACTIONS_LOGIN, "id": 1},
        "head": {"ref": "automation/codeql-autoheal-7-abcdef123456"},
    }
    assert preflight._bot_lane(pr) is None


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
