from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

from scripts import auto_trusted_report as reporter
from scripts import trusted_pr_control as control

ROOT = Path(__file__).resolve().parents[2]
HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
MERGE_SHA = "3" * 40
OTHER_SHA = "4" * 40
REPOSITORY = "portyu9/ai-qa-automation"
RUN_ID = 123
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}"
BOUND_RUN_URL = f"{RUN_URL}?pr=43&base={BASE_SHA}&head={HEAD_SHA}&merge={MERGE_SHA}"


def _pull_request_payload(*, head_sha: str = HEAD_SHA) -> dict[str, Any]:
    return {
        "number": 43,
        "state": "open",
        "head": {"sha": head_sha},
        "base": {"ref": "main", "sha": BASE_SHA},
    }


def _merge_ref_payload(*, sha: str = MERGE_SHA) -> dict[str, Any]:
    return {"ref": "refs/pull/43/merge", "object": {"sha": sha, "type": "commit"}}


def _merge_commit_payload() -> dict[str, Any]:
    return {
        "sha": MERGE_SHA,
        "parents": [{"sha": BASE_SHA}, {"sha": HEAD_SHA}],
        "tree": {"sha": "5" * 40},
    }


class FakeApi:
    current_payload: ClassVar[Mapping[str, Any]] = _pull_request_payload()
    payload_sequence: ClassVar[list[Mapping[str, Any]]] = []
    merge_ref_payload: ClassVar[Mapping[str, Any]] = _merge_ref_payload()
    merge_ref_sequence: ClassVar[list[Mapping[str, Any]]] = []
    main_ref_sequence: ClassVar[list[Mapping[str, Any]]] = []
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

    def get_json(self, path: str) -> Mapping[str, Any]:
        assert path == f"/repos/{REPOSITORY}/git/ref/heads/main"
        if type(self).main_ref_sequence:
            return type(self).main_ref_sequence.pop(0)
        return {"ref": "refs/heads/main", "object": {"sha": BASE_SHA, "type": "commit"}}

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        if type(self).payload_sequence:
            return type(self).payload_sequence.pop(0)
        return type(self).current_payload

    def fetch_pull_request_merge_ref(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        if type(self).merge_ref_sequence:
            return type(self).merge_ref_sequence.pop(0)
        return type(self).merge_ref_payload

    def fetch_git_commit(self, sha: str) -> Mapping[str, Any]:
        assert sha == MERGE_SHA
        return _merge_commit_payload()

    def post_status(
        self,
        *,
        sha: str,
        state: str,
        description: str,
        target_url: str,
    ) -> None:
        self.statuses.append(
            {
                "sha": sha,
                "state": state,
                "description": description,
                "target_url": target_url,
            }
        )


@pytest.fixture(autouse=True)
def _reset_fake_api() -> None:
    FakeApi.current_payload = _pull_request_payload()
    FakeApi.payload_sequence = []
    FakeApi.merge_ref_payload = _merge_ref_payload()
    FakeApi.merge_ref_sequence = []
    FakeApi.main_ref_sequence = []
    FakeApi.instances = []


def _subject() -> control.PullRequestSubject:
    return control.PullRequestSubject(43, HEAD_SHA, BASE_SHA, MERGE_SHA)


def _authorization_snapshot(*, merge_sha: str = MERGE_SHA) -> dict[str, Any]:
    return {
        "pr_number": 43,
        "head_sha": HEAD_SHA,
        "base_sha": BASE_SHA,
        "merge_sha": merge_sha,
        "trusted_sha": BASE_SHA,
        "protected_changes": ({"path": "scripts/auto_trusted_report.py", "change": "modified"},),
    }


def _report(
    monkeypatch: pytest.MonkeyPatch,
    *,
    result: str = "success",
    event: str = "workflow_run",
    lane: str = "owner-routine",
    run_id: int | str = RUN_ID,
    run_attempt: int | str = 1,
    target_url: str = RUN_URL,
) -> dict[str, Any]:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    if lane == reporter._preflight.PROTECTED_OWNER_LANE:
        authorization_snapshot = _authorization_snapshot()
        monkeypatch.setattr(
            reporter,
            "_require_protected_owner_authorization",
            lambda **_: authorization_snapshot,
        )
    return reporter.report_automatic_result(
        repository=REPOSITORY,
        token="app-token",
        workflow_event=event,
        expected_lane=lane,
        workflow_ref="refs/heads/main",
        workflow_run_id=run_id,
        workflow_run_attempt=run_attempt,
        expected=_subject(),
        job_results={"validation": result},
        target_url=target_url,
    )


@pytest.mark.parametrize(
    ("event", "lane"),
    [("workflow_run", "owner-routine"), ("schedule", "security-autoheal")],
)
def test_automatic_report_uses_shared_exact_subject_resolver(
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    lane: str,
) -> None:
    result = _report(monkeypatch, event=event, lane=lane)

    assert result["result"] == "SUCCESS"
    assert result["authorization_mode"] == "automatic-default-branch"
    assert result["status_target_url"] == BOUND_RUN_URL
    assert FakeApi.instances[0].statuses == [
        {
            "sha": HEAD_SHA,
            "state": "success",
            "description": "Automatic exact-subject trusted validation passed",
            "target_url": BOUND_RUN_URL,
        }
    ]


def test_protected_maintenance_report_is_explicit_and_exact_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(
        monkeypatch,
        event="schedule",
        lane=reporter._preflight.PROTECTED_OWNER_LANE,
    )

    assert result["result"] == "SUCCESS"
    assert result["authorization_mode"] == "explicit-default-branch-protected-maintenance"
    assert result["status_target_url"] == BOUND_RUN_URL
    assert FakeApi.instances[0].statuses == [
        {
            "sha": HEAD_SHA,
            "state": "success",
            "description": "Protected-maintenance exact-subject trusted validation passed",
            "target_url": BOUND_RUN_URL,
        }
    ]


def test_protected_maintenance_report_rejects_authorization_drift_before_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorization_snapshots = [
        _authorization_snapshot(),
        _authorization_snapshot(merge_sha=OTHER_SHA),
    ]

    def _next_authorization(**_: Any) -> dict[str, Any]:
        return authorization_snapshots.pop(0)

    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    monkeypatch.setattr(
        reporter,
        "_require_protected_owner_authorization",
        _next_authorization,
    )

    with pytest.raises(PermissionError, match="changed before status publication"):
        reporter.report_automatic_result(
            repository=REPOSITORY,
            token="app-token",
            workflow_event="schedule",
            expected_lane=reporter._preflight.PROTECTED_OWNER_LANE,
            workflow_ref="refs/heads/main",
            workflow_run_id=RUN_ID,
            workflow_run_attempt=1,
            expected=_subject(),
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )

    assert authorization_snapshots == []
    assert FakeApi.instances[0].statuses == []


@pytest.mark.parametrize(
    ("event", "ref", "match"),
    [
        ("repository_dispatch", "refs/heads/main", "workflow_run or schedule"),
        ("workflow_run", "refs/heads/feature", "refs/heads/main"),
    ],
)
def test_automatic_report_rejects_wrong_execution_context_before_api(
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    ref: str,
    match: str,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match=match):
        reporter.report_automatic_result(
            repository=REPOSITORY,
            token="app-token",
            workflow_event=event,
            expected_lane="owner-routine",
            workflow_ref=ref,
            workflow_run_id=RUN_ID,
            workflow_run_attempt=1,
            expected=_subject(),
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


@pytest.mark.parametrize(
    "main_sequence",
    [
        [{"ref": "refs/heads/main", "object": {"sha": OTHER_SHA, "type": "commit"}}],
        [
            {"ref": "refs/heads/main", "object": {"sha": BASE_SHA, "type": "commit"}},
            {"ref": "refs/heads/main", "object": {"sha": OTHER_SHA, "type": "commit"}},
        ],
    ],
)
def test_automatic_report_fails_closed_on_current_main_drift(
    monkeypatch: pytest.MonkeyPatch,
    main_sequence: list[Mapping[str, Any]],
) -> None:
    FakeApi.main_ref_sequence = main_sequence

    with pytest.raises(ValueError, match="current main changed after authorization"):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_automatic_report_fails_closed_on_final_subject_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.payload_sequence = [
        _pull_request_payload(),
        _pull_request_payload(head_sha=OTHER_SHA),
    ]

    with pytest.raises(ValueError, match="subject changed after authorization"):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_automatic_report_fails_closed_on_final_merge_ref_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeApi.merge_ref_sequence = [_merge_ref_payload(), _merge_ref_payload(sha=OTHER_SHA)]

    with pytest.raises(ValueError, match="before status publication"):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


def test_automatic_failed_validation_posts_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(monkeypatch, result="failure")

    assert result["result"] == "FAILURE"
    assert FakeApi.instances[0].statuses[0]["state"] == "failure"


@pytest.mark.parametrize(
    ("event", "lane"),
    [
        ("workflow_run", "owner-routine"),
        ("schedule", "security-autoheal"),
        ("schedule", reporter._preflight.PROTECTED_OWNER_LANE),
    ],
)
def test_automatic_report_rejects_rerun_before_status_publication(
    monkeypatch: pytest.MonkeyPatch,
    event: str,
    lane: str,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="workflow run attempt 1"):
        _report(monkeypatch, event=event, lane=lane, run_attempt=2)
    assert FakeApi.instances == []


def test_automatic_report_rejects_target_url_not_bound_to_current_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="exact reporter workflow run"):
        _report(
            monkeypatch,
            run_id=RUN_ID,
            target_url=f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID + 1}",
        )
    assert FakeApi.instances == []


def test_automatic_report_rejects_invalid_validation_contract_before_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(ValueError, match="exactly"):
        reporter.report_automatic_result(
            repository=REPOSITORY,
            token="app-token",
            workflow_event="workflow_run",
            expected_lane="owner-routine",
            workflow_ref="refs/heads/main",
            workflow_run_id=RUN_ID,
            workflow_run_attempt=1,
            expected=_subject(),
            job_results={"validation": "success", "other": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


def test_owner_routine_report_requires_workflow_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="owner-routine status publication requires workflow_run"):
        _report(monkeypatch, event="schedule", lane="owner-routine")
    assert FakeApi.instances == []


def test_protected_maintenance_report_requires_scheduled_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(PermissionError, match="requires trusted schedule"):
        reporter.report_automatic_result(
            repository=REPOSITORY,
            token="app-token",
            workflow_event="workflow_run",
            expected_lane=reporter._preflight.PROTECTED_OWNER_LANE,
            workflow_ref="refs/heads/main",
            workflow_run_id=RUN_ID,
            workflow_run_attempt=1,
            expected=_subject(),
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


def test_automatic_report_cli_loads_shared_control_under_python_safe_path() -> None:
    env = dict(os.environ)
    env["PYTHONSAFEPATH"] = "1"
    completed = subprocess.run(
        [sys.executable, "scripts/auto_trusted_report.py", "--help"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Automatic trusted PR status reporter" in completed.stdout
