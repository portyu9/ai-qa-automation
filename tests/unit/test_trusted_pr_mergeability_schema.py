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
    payload: ClassVar[Mapping[str, Any]]
    instances: ClassVar[list[FakeApi]] = []

    def __init__(self, *, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token
        self.fetch_count = 0
        self.statuses: list[dict[str, str]] = []
        type(self).instances.append(self)

    def fetch_pull_request(self, number: int) -> Mapping[str, Any]:
        assert number == 43
        self.fetch_count += 1
        return type(self).payload

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


def _payload() -> dict[str, Any]:
    return {
        "number": 43,
        "state": "open",
        "head": {"sha": HEAD_SHA},
        "base": {"ref": "main", "sha": BASE_SHA},
        "merge_commit_sha": MERGE_SHA,
        "mergeable": True,
    }


@pytest.mark.parametrize("missing_field", ["mergeable", "merge_commit_sha"])
def test_missing_mergeability_schema_is_nonretryable(
    monkeypatch: pytest.MonkeyPatch,
    missing_field: str,
) -> None:
    payload = _payload()
    payload.pop(missing_field)
    FakeApi.payload = payload
    FakeApi.instances = []
    sleeps: list[float] = []
    monkeypatch.setattr(control, "GitHubApi", FakeApi)
    monkeypatch.setattr(control.time, "sleep", sleeps.append)

    with pytest.raises(ValueError, match="field is required"):
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

    assert len(FakeApi.instances) == 1
    assert FakeApi.instances[0].fetch_count == 1
    assert FakeApi.instances[0].statuses == []
    assert sleeps == []
