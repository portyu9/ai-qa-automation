from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

import pytest

from scripts import trusted_pr_control as control

HEAD_SHA = "1" * 40
BASE_SHA = "2" * 40
MERGE_SHA = "3" * 40
REPOSITORY = "portyu9/ai-qa-automation"
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/123"


class FakeApi:
    pr_payload: ClassVar[Mapping[str, Any]]
    merge_ref_payload: ClassVar[Mapping[str, Any]]
    merge_commit_payload: ClassVar[Mapping[str, Any]]
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        return type(self).pr_payload

    def fetch_pull_request_merge_ref(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        return type(self).merge_ref_payload

    def fetch_git_commit(self, sha: str) -> Mapping[str, Any]:
        assert sha == MERGE_SHA
        return type(self).merge_commit_payload

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


def _pr_payload() -> dict[str, Any]:
    return {
        "number": 43,
        "state": "open",
        "head": {"sha": HEAD_SHA},
        "base": {"ref": "main", "sha": BASE_SHA},
    }


def _merge_ref_payload() -> dict[str, Any]:
    return {
        "ref": "refs/pull/43/merge",
        "object": {"type": "commit", "sha": MERGE_SHA},
    }


def _merge_commit_payload() -> dict[str, Any]:
    return {
        "sha": MERGE_SHA,
        "parents": [{"sha": BASE_SHA}, {"sha": HEAD_SHA}],
    }


def _report(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeApi.instances = []
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    control.report_authorized_result(
        repository=REPOSITORY,
        token="token",
        actor="portyu9",
        repository_owner="portyu9",
        workflow_event="repository_dispatch",
        workflow_ref="refs/heads/main",
        expected=control.PullRequestSubject(
            number=43,
            head_sha=HEAD_SHA,
            base_sha=BASE_SHA,
            merge_sha=MERGE_SHA,
        ),
        authorized=True,
        job_results={"validation": "success"},
        target_url=RUN_URL,
    )


@pytest.mark.parametrize("missing_field", ["ref", "object"])
def test_missing_merge_ref_schema_is_non_authoritative(
    monkeypatch: pytest.MonkeyPatch,
    missing_field: str,
) -> None:
    FakeApi.pr_payload = _pr_payload()
    merge_ref = _merge_ref_payload()
    merge_ref.pop(missing_field)
    FakeApi.merge_ref_payload = merge_ref
    FakeApi.merge_commit_payload = _merge_commit_payload()

    with pytest.raises(ValueError):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []


@pytest.mark.parametrize("missing_field", ["sha", "parents"])
def test_missing_merge_commit_schema_is_non_authoritative(
    monkeypatch: pytest.MonkeyPatch,
    missing_field: str,
) -> None:
    FakeApi.pr_payload = _pr_payload()
    FakeApi.merge_ref_payload = _merge_ref_payload()
    merge_commit = _merge_commit_payload()
    merge_commit.pop(missing_field)
    FakeApi.merge_commit_payload = merge_commit

    with pytest.raises(ValueError):
        _report(monkeypatch)

    assert FakeApi.instances[0].statuses == []
