from __future__ import annotations

import json

import pytest

from scripts.trusted_gate_service import github as github_module
from scripts.trusted_gate_service.core import EXPECTED_REPOSITORY, EXPECTED_REPOSITORY_ID
from scripts.trusted_gate_service.github import GitHubClient, GitHubProtocolError

HEAD = "1" * 40
RUN_ID = 918
INSTALLATION_ID = 12345


class _Provider:
    def installation_token(self) -> str:
        return "test-token"


def _successful_run() -> dict[str, object]:
    return {
        "id": RUN_ID,
        "workflow_id": 339754724,
        "name": "CI — ƳƤ AI QA Automation Framework",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "success",
        "repository": {
            "id": EXPECTED_REPOSITORY_ID,
            "full_name": EXPECTED_REPOSITORY,
        },
        "head_repository": {"full_name": EXPECTED_REPOSITORY},
        "actor": {"login": "portyu9"},
        "triggering_actor": {"login": "portyu9"},
        "head_sha": HEAD,
    }


def test_commit_pull_request_resolution_fails_closed_at_page_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GitHubClient(
        token_provider=_Provider(),  # type: ignore[arg-type]
        installation_id=INSTALLATION_ID,
    )
    monkeypatch.setattr(client, "get_json", lambda _path: _successful_run())
    saturated = json.dumps([{} for _ in range(100)]).encode("utf-8")
    monkeypatch.setattr(
        github_module,
        "_request_bytes",
        lambda **_kwargs: saturated,
    )

    with pytest.raises(
        GitHubProtocolError,
        match="pagination bound",
    ):
        client.resolve_subject(run_id=RUN_ID, event_head_sha=HEAD)
