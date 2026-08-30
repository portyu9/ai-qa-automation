from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

import pytest

from scripts import auto_trusted_report as reporter
from scripts import trusted_pr_control as control

HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
MERGE_SHA = "3" * 40
OTHER_SHA = "4" * 40
REPOSITORY = "portyu9/ai-qa-automation"
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/123"


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
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

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
    FakeApi.instances = []


def _subject() -> control.PullRequestSubject:
    return control.PullRequestSubject(43, HEAD_SHA, BASE_SHA, MERGE_SHA)


def _report(monkeypatch: pytest.MonkeyPatch, *, result: str = "success") -> dict[str, Any]:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    return reporter.report_automatic_result(
        repository=REPOSITORY,
        token="app-token",
        workflow_event="workflow_run",
        workflow_ref="refs/heads/main",
        expected=_subject(),
        job_results={"validation": result},
        target_url=RUN_URL,
    )


def test_automatic_report_uses_shared_exact_subject_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _report(monkeypatch)

    assert result["result"] == "SUCCESS"
    assert result["authorization_mode"] == "automatic-default-branch"
    assert FakeApi.instances[0].statuses == [
        {
            "sha": HEAD_SHA,
            "state": "success",
            "description": "Automatic exact-subject trusted validation passed",
            "target_url": RUN_URL,
        }
    ]


@pytest.mark.parametrize(
    ("event", "ref", "match"),
    [
        ("repository_dispatch", "refs/heads/main", "workflow_run"),
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
            workflow_ref=ref,
            expected=_subject(),
            job_results={"validation": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []


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


def test_automatic_report_rejects_invalid_validation_contract_before_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporter, "GitHubApi", FakeApi)
    with pytest.raises(ValueError, match="exactly"):
        reporter.report_automatic_result(
            repository=REPOSITORY,
            token="app-token",
            workflow_event="workflow_run",
            workflow_ref="refs/heads/main",
            expected=_subject(),
            job_results={"validation": "success", "other": "success"},
            target_url=RUN_URL,
        )
    assert FakeApi.instances == []
