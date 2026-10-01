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
PROTECTED_COMMENT_ID = 701


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

    def list_all(
        self, path: str, *, max_pages: int = preflight.MAX_API_PAGES
    ) -> list[dict[str, Any]]:
        expected = (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls"
            f"?state=open&base={preflight.EXPECTED_DEFAULT_BRANCH}"
        )
        if path == expected and max_pages == 1:
            return []
        raise AssertionError(f"unexpected fake list path: {path} max_pages={max_pages}")


class GovernanceWakeFakeAPI(FakeAPI):
    def __init__(
        self,
        responses: dict[str, Any],
        pulls: list[dict[str, Any]],
        checks: dict[str, list[dict[str, Any]]],
    ) -> None:
        super().__init__(responses)
        self.pulls = pulls
        self.checks = checks
        self.list_calls: list[tuple[str, int]] = []

    def list_all(
        self, path: str, *, max_pages: int = preflight.MAX_API_PAGES
    ) -> list[dict[str, Any]]:
        self.list_calls.append((path, max_pages))
        pulls_path = (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls"
            f"?state=open&base={preflight.EXPECTED_DEFAULT_BRANCH}"
        )
        if path == pulls_path and max_pages == 1:
            return deepcopy(self.pulls)
        if path in self.checks and max_pages == 2:
            return deepcopy(self.checks[path])
        raise AssertionError(f"unexpected governance wake list path: {path} max_pages={max_pages}")


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


class ScheduledOwnerFakeAPI(FakeAPI):
    def __init__(
        self,
        responses: dict[str, Any],
        pulls: list[dict[str, Any]],
        comments: list[dict[str, Any]],
        statuses: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(responses)
        self.pulls = pulls
        self.comments = comments
        self.statuses = [] if statuses is None else statuses
        self.list_calls: list[tuple[str, int]] = []

    def list_all(
        self, path: str, *, max_pages: int = preflight.MAX_API_PAGES
    ) -> list[dict[str, Any]]:
        self.list_calls.append((path, max_pages))
        pulls_path = (
            f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls"
            f"?state=open&base={preflight.EXPECTED_DEFAULT_BRANCH}"
        )
        if path == pulls_path and max_pages == 1:
            return deepcopy(self.pulls)
        if (
            path == f"/repos/{preflight.EXPECTED_REPOSITORY}/issues/65/comments"
            and max_pages == preflight.MAX_API_PAGES
        ):
            return deepcopy(self.comments)
        if (
            path == f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/statuses"
            and max_pages == preflight.MAX_API_PAGES
        ):
            return deepcopy(self.statuses)
        raise AssertionError(f"unexpected scheduled-owner list path: {path} max_pages={max_pages}")


class SequencedScheduledOwnerFakeAPI(ScheduledOwnerFakeAPI):
    def __init__(
        self,
        responses: dict[str, Any],
        pulls: list[dict[str, Any]],
        comments: list[dict[str, Any]],
        statuses: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(responses, pulls, comments, statuses)
        self.pull_get_count = 0

    def get(self, path: str) -> Any:
        pull_path = f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"
        if path != pull_path:
            return super().get(path)
        self.calls.append(path)
        self.pull_get_count += 1
        payload = deepcopy(self.responses[path])
        if self.pull_get_count >= 3:
            payload["user"]["type"] = "Bot"
        return payload


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
        "user": {
            "login": preflight.EXPECTED_OWNER,
            "id": preflight.EXPECTED_OWNER_ID,
            "type": "User",
        },
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


def _dependabot_actions_responses(
    *,
    changed_path: str | None = ".github",
    head_ref: str = "dependabot/github_actions/routine-actions-4b2c77c676",
) -> dict[str, Any]:
    responses = _responses(changed_path=changed_path)
    bot = {"login": preflight.DEPENDABOT_LOGIN, "id": preflight.DEPENDABOT_USER_ID}
    run = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run["actor"] = dict(bot)
    run["triggering_actor"] = dict(bot)
    candidate = responses[_pulls_path()][0]
    candidate["head"]["ref"] = head_ref
    live = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    live["user"] = dict(bot)
    live["head"]["ref"] = head_ref
    return responses


def _protected_comment_body(**overrides: str) -> str:
    fields = {
        "authorization": preflight.PROTECTED_OWNER_REASON,
        "pr_number": "65",
        "head_sha": HEAD,
        "base_sha": BASE,
        "merge_sha": MERGE,
    }
    fields.update(overrides)
    return (
        f"/trusted-maintenance authorization={fields['authorization']} "
        f"pr={fields['pr_number']} head={fields['head_sha']} "
        f"base={fields['base_sha']} merge={fields['merge_sha']}"
    )


def _protected_comment_event(**command_overrides: str) -> dict[str, Any]:
    body = _protected_comment_body(**command_overrides)
    issue_url = f"https://api.github.com/repos/{preflight.EXPECTED_REPOSITORY}/issues/65"
    owner = {
        "login": preflight.EXPECTED_OWNER,
        "id": preflight.EXPECTED_OWNER_ID,
        "type": "User",
    }
    return {
        "action": "created",
        "repository": {"full_name": preflight.EXPECTED_REPOSITORY},
        "sender": dict(owner),
        "issue": {
            "number": 65,
            "pull_request": {
                "url": f"https://api.github.com/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"
            },
        },
        "comment": {
            "id": PROTECTED_COMMENT_ID,
            "body": body,
            "issue_url": issue_url,
            "user": dict(owner),
            "created_at": "2026-09-30T12:00:00Z",
            "updated_at": "2026-09-30T12:00:00Z",
        },
    }


def _protected_comment_responses(
    *,
    changed_path: str | None = ".github",
    **command_overrides: str,
) -> dict[str, Any]:
    responses = _responses(changed_path=changed_path)
    event = _protected_comment_event(**command_overrides)
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/issues/comments/{PROTECTED_COMMENT_ID}"] = (
        deepcopy(event["comment"])
    )
    return responses


def _configure_protected_comment_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv("GITHUB_SHA", BASE)
    monkeypatch.setenv("GITHUB_ACTOR", preflight.EXPECTED_OWNER)
    monkeypatch.setenv("GITHUB_TRIGGERING_ACTOR", preflight.EXPECTED_OWNER)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        f"{preflight.EXPECTED_REPOSITORY}/.github/workflows/trusted-pr-auto.yml@refs/heads/main",
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


def test_owner_subject_resolution_rejects_non_user_principal_type() -> None:
    responses = _responses()
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["user"]["type"] = "Bot"

    with pytest.raises(ValueError, match="exact repository owner identity"):
        preflight.evaluate_admission(FakeAPI(responses), event=_event())


def test_exact_dependabot_actions_ci_wake_selects_only_live_bot_subject() -> None:
    admission = preflight.evaluate_admission(
        FakeAPI(_dependabot_actions_responses()),
        event=_event(),
    )

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == "dependabot-actions"
    assert admission.qualification_ready is True
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.trusted_sha == BASE
    assert admission.protected_changes == (
        {
            "path": ".github",
            "base_oid": UNCHANGED,
            "subject_oid": "7" * 40,
        },
    )


def test_dependabot_ci_wake_rejects_non_actions_dependabot_pr() -> None:
    responses = _dependabot_actions_responses(
        changed_path=None,
        head_ref="dependabot/pip/routine-dependencies-71a4d8ee02",
    )

    assert preflight.evaluate_admission(FakeAPI(responses), event=_event()) is None


def test_dependabot_ci_wake_rejects_triggering_actor_drift() -> None:
    responses = _dependabot_actions_responses(changed_path=None)
    responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["triggering_actor"] = {
        "login": preflight.EXPECTED_OWNER,
        "id": preflight.EXPECTED_OWNER_ID,
    }

    assert preflight.evaluate_admission(FakeAPI(responses), event=_event()) is None


def test_owner_ci_wake_cannot_reclassify_dependabot_actions_pr() -> None:
    responses = _dependabot_actions_responses(changed_path=None)
    owner = {"login": preflight.EXPECTED_OWNER, "id": preflight.EXPECTED_OWNER_ID}
    run = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run["actor"] = dict(owner)
    run["triggering_actor"] = dict(owner)

    assert preflight.evaluate_admission(FakeAPI(responses), event=_event()) is None


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


def _governance_wake_api(*, wake_conclusion: str = "neutral") -> GovernanceWakeFakeAPI:
    responses = _responses()
    run = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run.update(
        {
            "workflow_id": preflight.EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_ID,
            "name": preflight.EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_NAME,
            "path": preflight.EXPECTED_DEPENDENCY_GOVERNANCE_WORKFLOW_PATH,
            "event": "workflow_run",
            "head_branch": preflight.EXPECTED_DEFAULT_BRANCH,
            "head_sha": BASE,
        }
    )
    live = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    live["user"] = {
        "login": preflight.PROTECTED_REMEDIATION_BOT_LOGIN,
        "id": preflight.PROTECTED_REMEDIATION_BOT_USER_ID,
    }
    live["head"]["ref"] = "automation/dependency-promotion-179-abcdef123456"
    summary = deepcopy(live)
    check_path = f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/check-runs?filter=all"
    wake_external_id = (
        f"{preflight.DEPENDENCY_PROMOTION_WAKE_PREFIX}:{HEAD}:{BASE}:trusted-gate:42:1"
    )
    checks = {
        check_path: [
            {
                "id": 77,
                "name": preflight.DEPENDENCY_PROMOTION_WAKE_CHECK,
                "head_sha": HEAD,
                "external_id": wake_external_id,
                "status": "completed",
                "conclusion": wake_conclusion,
                "details_url": (f"https://github.com/{preflight.EXPECTED_REPOSITORY}/runs/77"),
                "app": {"id": preflight.GITHUB_ACTIONS_APP_ID, "slug": "github-actions"},
            }
        ]
    }
    return GovernanceWakeFakeAPI(responses, [summary], checks)


def test_successful_governance_wake_selects_exact_dependency_promotion() -> None:
    api = _governance_wake_api()
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    admission = preflight.evaluate_admission(api, event=event)

    assert admission is not None
    assert admission.eligible is True
    assert admission.qualification_ready is True
    assert admission.lane == "dependency-promotion"
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE


def test_governance_wake_rejects_noncanonical_check_url() -> None:
    api = _governance_wake_api()
    check_path = f"/repos/{preflight.EXPECTED_REPOSITORY}/commits/{HEAD}/check-runs?filter=all"
    api.checks[check_path][0]["details_url"] = "https://example.invalid/forged"
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_stale_successful_governance_noop_cannot_wake_trusted_validation() -> None:
    api = _governance_wake_api()
    stale_sha = "c" * 40
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["head_sha"] = stale_sha
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": stale_sha}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_dependency_governance_manual_dispatch_cannot_wake_trusted_validation() -> None:
    api = _governance_wake_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["event"] = (
        "workflow_dispatch"
    )
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_successful_governance_wake_rejects_legacy_github_actions_promotion() -> None:
    api = _governance_wake_api()
    legacy = {
        "login": preflight.GITHUB_ACTIONS_LOGIN,
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    live = api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    live["user"] = legacy
    api.pulls[0]["user"] = legacy
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_governance_wake_actor_is_not_admission_authority() -> None:
    api = _governance_wake_api()
    run = api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run["actor"] = {
        "login": preflight.GITHUB_ACTIONS_LOGIN,
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    run["triggering_actor"] = {
        "login": preflight.GITHUB_ACTIONS_LOGIN,
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    admission = preflight.evaluate_admission(api, event=event)

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == "dependency-promotion"
    assert admission.pr_number == 65


def test_governance_wake_check_is_neutral_only_and_non_authoritative() -> None:
    api = _governance_wake_api(wake_conclusion="success")
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_startup_failed_governance_run_cannot_wake_trusted_validation() -> None:
    api = _governance_wake_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["conclusion"] = (
        "startup_failure"
    )
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def test_failed_governance_run_cannot_wake_trusted_validation() -> None:
    api = _governance_wake_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["conclusion"] = (
        "failure"
    )
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": BASE}}

    assert preflight.evaluate_admission(api, event=event) is None


def _protected_owner_reconciliation_event() -> dict[str, Any]:
    return {"action": "completed", "workflow_run": {"id": 42, "head_sha": HEAD}}


def _protected_owner_reconciliation_api(
    *,
    comments: list[dict[str, Any]] | None = None,
    statuses: list[dict[str, Any]] | None = None,
) -> ScheduledOwnerFakeAPI:
    responses = _protected_comment_responses()
    owner = {
        "login": preflight.EXPECTED_OWNER,
        "id": preflight.EXPECTED_OWNER_ID,
        "type": "User",
    }
    run = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run.update(
        {
            "workflow_id": preflight.EXPECTED_CI_WORKFLOW_ID,
            "name": preflight.EXPECTED_CI_WORKFLOW_NAME,
            "path": preflight.EXPECTED_CI_WORKFLOW_PATH,
            "event": "pull_request",
            "head_branch": "owner-protected-change",
            "head_sha": HEAD,
            "conclusion": "success",
            "actor": dict(owner),
            "triggering_actor": dict(owner),
        }
    )
    live = responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]
    live["user"]["type"] = "User"
    summary = deepcopy(live)
    summary.pop("mergeable", None)
    event = _protected_comment_event()
    default_comments = [deepcopy(event["comment"])]
    return ScheduledOwnerFakeAPI(
        responses,
        [summary],
        default_comments if comments is None else comments,
        statuses,
    )


def _assert_protected_owner_authority_absent(admission: preflight.Admission | None) -> None:
    assert admission is not None
    assert admission.lane == "owner-routine"
    assert admission.eligible is False
    assert admission.protected_changes


def test_reviewed_ci_wake_rejects_source_workflow_id_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    run = api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run["workflow_id"] = preflight.EXPECTED_CI_WORKFLOW_ID + 1

    assert preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event()) is None


def test_reviewed_ci_wake_rejects_source_path_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    run = api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    run["path"] = ".github/workflows/not-ci.yml"

    assert preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event()) is None


def test_reviewed_ci_wake_authorization_selects_exact_protected_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    admission = preflight.evaluate_admission(
        _protected_owner_reconciliation_api(), event=_protected_owner_reconciliation_event()
    )

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == preflight.PROTECTED_OWNER_LANE
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.protected_changes


def test_startup_failed_reviewed_ci_wake_cannot_reconcile_protected_owner_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["conclusion"] = (
        "startup_failure"
    )

    assert preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event()) is None


def test_successful_reviewed_ci_wake_reconciles_pending_protected_owner_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    admission = preflight.evaluate_admission(
        _protected_owner_reconciliation_api(), event=_protected_owner_reconciliation_event()
    )

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == preflight.PROTECTED_OWNER_LANE
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE


def test_dependabot_ci_wake_cannot_select_protected_owner_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    run = api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]
    wake_head = "9" * 40
    dependabot = {
        "login": preflight.DEPENDABOT_LOGIN,
        "id": preflight.DEPENDABOT_USER_ID,
        "type": "Bot",
    }
    run.update(
        {
            "workflow_id": preflight.EXPECTED_CI_WORKFLOW_ID,
            "name": preflight.EXPECTED_CI_WORKFLOW_NAME,
            "path": preflight.EXPECTED_CI_WORKFLOW_PATH,
            "event": "pull_request",
            "head_branch": "dependabot/github_actions/actions/checkout-7",
            "head_sha": wake_head,
            "conclusion": "success",
            "actor": dict(dependabot),
            "triggering_actor": dict(dependabot),
        }
    )
    event = {"action": "completed", "workflow_run": {"id": 42, "head_sha": wake_head}}

    admission = preflight.evaluate_admission(api, event=event)

    assert admission is not None
    assert admission.lane == preflight.PROTECTED_OWNER_LANE
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.head_sha != wake_head
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE


def test_successful_reviewed_ci_wake_has_no_protected_authority_without_exact_comment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api(comments=[])

    admission = preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())

    assert admission is not None
    assert admission.lane == "owner-routine"
    assert admission.eligible is False
    assert admission.protected_changes


def test_failed_reviewed_ci_wake_cannot_reconcile_protected_owner_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/actions/runs/42"]["conclusion"] = (
        "failure"
    )

    assert preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event()) is None


def test_protected_owner_reconciliation_authorization_requires_user_type_in_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    api.pulls[0]["user"]["type"] = "Bot"

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())
    )


def test_protected_owner_reconciliation_authorization_requires_user_type_after_live_refetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"]["user"]["type"] = "Bot"

    with pytest.raises(ValueError, match="exact repository owner identity"):
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())


def test_protected_owner_reconciliation_authorization_reproves_user_type_at_subject_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    base_api = _protected_owner_reconciliation_api()
    api = SequencedScheduledOwnerFakeAPI(
        base_api.responses,
        base_api.pulls,
        base_api.comments,
        base_api.statuses,
    )

    with pytest.raises(ValueError, match="exact repository owner identity"):
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())

    assert api.pull_get_count == 3


def test_protected_owner_reconciliation_authorization_ignores_stale_exact_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    stale = deepcopy(_protected_comment_event(base_sha="8" * 40)["comment"])
    api = _protected_owner_reconciliation_api(comments=[stale])

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())
    )


def test_protected_owner_reconciliation_authorization_rejects_live_comment_provenance_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    api.responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/issues/comments/{PROTECTED_COMMENT_ID}"][
        "user"
    ] = {"login": "attacker", "id": 999, "type": "User"}

    with pytest.raises(ValueError, match="changed or lost provenance"):
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())


def test_protected_owner_reconciliation_authorization_ignores_edited_comment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    comment = deepcopy(_protected_comment_event()["comment"])
    comment["updated_at"] = "2026-09-30T12:01:00Z"

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(comments=[comment]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_authorization_rejects_comment_edited_after_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    api = _protected_owner_reconciliation_api()
    live = api.responses[
        f"/repos/{preflight.EXPECTED_REPOSITORY}/issues/comments/{PROTECTED_COMMENT_ID}"
    ]
    live["updated_at"] = "2026-09-30T12:01:00Z"

    with pytest.raises(ValueError, match="must be unedited"):
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())


def test_protected_owner_reconciliation_authorization_ignores_non_owner_comment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    comment = deepcopy(_protected_comment_event()["comment"])
    comment["user"] = {"login": "attacker", "id": 999, "type": "User"}

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(comments=[comment]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_authorization_rejects_ambiguous_live_comments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    first = deepcopy(_protected_comment_event()["comment"])
    second = deepcopy(first)
    second["id"] = PROTECTED_COMMENT_ID + 1
    api = _protected_owner_reconciliation_api(comments=[first, second])
    api.responses[
        f"/repos/{preflight.EXPECTED_REPOSITORY}/issues/comments/{PROTECTED_COMMENT_ID + 1}"
    ] = deepcopy(second)

    with pytest.raises(ValueError, match="authorization is ambiguous"):
        preflight.evaluate_admission(api, event=_protected_owner_reconciliation_event())


def test_protected_owner_reconciliation_authorization_rejects_rerun_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")

    with pytest.raises(ValueError, match="cannot be rerun"):
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(), event=_protected_owner_reconciliation_event()
        )


def test_protected_owner_reconciliation_authorization_is_consumed_by_exact_trusted_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    status = {
        "id": 901,
        "state": "success",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/123"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(statuses=[status]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_authorization_is_consumed_by_exact_trusted_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    status = {
        "id": 903,
        "state": "failure",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/125"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(statuses=[status]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_exact_terminal_status_is_not_resurrected_by_newer_stale_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    exact = {
        "id": 904,
        "state": "failure",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/126"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }
    stale = {
        "id": 905,
        "state": "success",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/127"
            f"?pr=65&base={'8' * 40}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(statuses=[stale, exact]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_authorization_is_consumed_by_exact_trusted_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    status = {
        "id": 906,
        "state": "error",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/128"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(statuses=[status]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_exact_terminal_status_is_not_resurrected_by_newer_exact_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    terminal = {
        "id": 907,
        "state": "failure",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/129"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }
    pending = {
        "id": 908,
        "state": "pending",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/130"
            f"?pr=65&base={BASE}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    _assert_protected_owner_authority_absent(
        preflight.evaluate_admission(
            _protected_owner_reconciliation_api(statuses=[pending, terminal]),
            event=_protected_owner_reconciliation_event(),
        )
    )


def test_protected_owner_reconciliation_stale_trusted_status_does_not_suppress_revalidation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    status = {
        "id": 902,
        "state": "success",
        "context": preflight.TRUSTED_STATUS_CONTEXT,
        "target_url": (
            f"https://github.com/{preflight.EXPECTED_REPOSITORY}/actions/runs/124"
            f"?pr=65&base={'8' * 40}&head={HEAD}&merge={MERGE}"
        ),
        "creator": {
            "login": preflight.TRUSTED_STATUS_BOT_LOGIN,
            "id": preflight.TRUSTED_STATUS_BOT_USER_ID,
            "type": "Bot",
        },
    }

    admission = preflight.evaluate_admission(
        _protected_owner_reconciliation_api(statuses=[status]),
        event=_protected_owner_reconciliation_event(),
    )
    assert admission is not None
    assert admission.lane == preflight.PROTECTED_OWNER_LANE


def test_issue_comment_event_is_not_a_runtime_admission_path() -> None:
    with pytest.raises(ValueError, match="workflow_run or schedule only"):
        preflight.evaluate_admission(
            FakeAPI(_responses()),
            event={},
            event_name="issue_comment",
        )


def test_scheduled_reconciliation_selects_exact_protected_owner_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_protected_comment_env(monkeypatch)
    admission = preflight.evaluate_admission(
        _protected_owner_reconciliation_api(),
        event={},
        event_name="schedule",
    )

    assert admission is not None
    assert admission.eligible is True
    assert admission.lane == preflight.PROTECTED_OWNER_LANE
    assert admission.pr_number == 65
    assert admission.head_sha == HEAD
    assert admission.base_sha == BASE
    assert admission.merge_sha == MERGE
    assert admission.protected_changes


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


def test_scheduled_reconciliation_ignores_advanced_security_reporting_actor() -> None:
    responses = _responses()
    summary = deepcopy(responses[f"/repos/{preflight.EXPECTED_REPOSITORY}/pulls/65"])
    summary["user"] = {
        "login": "github-advanced-security[bot]",
        "id": preflight.GITHUB_ACTIONS_USER_ID,
    }
    summary["head"]["ref"] = "automation/codeql-autoheal-7-abcdef123456"
    api = ScheduledFakeAPI(responses, [summary])

    admission = preflight.evaluate_admission(api, event={}, event_name="schedule")

    assert admission is None
    assert api.calls == [f"/repos/{preflight.EXPECTED_REPOSITORY}/git/ref/heads/main"]


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


def test_stale_workflow_head_after_pr_moves_is_safe_noop() -> None:
    responses = _responses()
    responses[_pulls_path()][0]["head"]["sha"] = "8" * 40

    assert preflight.evaluate_admission(FakeAPI(responses), event=_event()) is None


def test_ambiguous_pull_request_resolution_fails_closed() -> None:
    responses = _responses()
    responses[_pulls_path()].append(deepcopy(responses[_pulls_path()][0]))
    responses[_pulls_path()][1]["number"] = 66

    with pytest.raises(ValueError, match="maps to multiple"):
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
            {
                "login": preflight.PROTECTED_REMEDIATION_BOT_LOGIN,
                "id": preflight.PROTECTED_REMEDIATION_BOT_USER_ID,
            },
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


def test_promotion_staging_base_has_no_governed_lane() -> None:
    pr = {
        "user": {
            "login": preflight.PROTECTED_REMEDIATION_BOT_LOGIN,
            "id": preflight.PROTECTED_REMEDIATION_BOT_USER_ID,
        },
        "head": {"ref": "automation/dependency-promotion-base-171-abcdef123456"},
    }

    assert preflight._bot_lane(pr) is None


def test_legacy_github_actions_promotion_has_no_governed_lane() -> None:
    pr = {
        "user": {
            "login": preflight.GITHUB_ACTIONS_LOGIN,
            "id": preflight.GITHUB_ACTIONS_USER_ID,
        },
        "head": {"ref": "automation/dependency-promotion-171-abcdef123456"},
    }

    assert preflight._bot_lane(pr) is None


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


def test_protected_remediation_lane_requires_exact_pinned_app_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login = preflight.PROTECTED_REMEDIATION_BOT_LOGIN
    user_id = preflight.PROTECTED_REMEDIATION_BOT_USER_ID
    branch = "automation/protected-security-remediation-17-" + ("a" * 64) + "-a1"
    monkeypatch.delenv(preflight.PROTECTED_REMEDIATION_BOT_LOGIN_ENV, raising=False)
    monkeypatch.delenv(preflight.PROTECTED_REMEDIATION_BOT_ID_ENV, raising=False)

    assert (
        preflight._bot_lane({"user": {"login": login, "id": user_id}, "head": {"ref": branch}})
        == "protected-security-remediation"
    )
    assert (
        preflight._bot_lane({"user": {"login": login, "id": user_id + 1}, "head": {"ref": branch}})
        is None
    )

    monkeypatch.setenv(preflight.PROTECTED_REMEDIATION_BOT_LOGIN_ENV, login)
    with pytest.raises(ValueError, match="partially configured"):
        preflight._bot_lane({"user": {"login": login, "id": user_id}, "head": {"ref": branch}})

    monkeypatch.setenv(preflight.PROTECTED_REMEDIATION_BOT_ID_ENV, str(user_id + 1))
    with pytest.raises(ValueError, match="drifted from trusted policy"):
        preflight._bot_lane({"user": {"login": login, "id": user_id}, "head": {"ref": branch}})


@pytest.mark.parametrize(
    "login",
    ["github-actions[bot]", "dependabot[bot]", "trusted-pr-gate[bot]"],
)
def test_protected_remediation_lane_rejects_collapsed_author_identity(
    monkeypatch: pytest.MonkeyPatch, login: str
) -> None:
    branch = "automation/protected-security-remediation-17-" + ("b" * 64) + "-a1"
    monkeypatch.setenv(preflight.PROTECTED_REMEDIATION_BOT_LOGIN_ENV, login)
    monkeypatch.setenv(preflight.PROTECTED_REMEDIATION_BOT_ID_ENV, "42")

    with pytest.raises(ValueError, match="drifted from trusted policy"):
        preflight._bot_lane({"user": {"login": login, "id": 42}, "head": {"ref": branch}})
