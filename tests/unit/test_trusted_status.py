from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TRUSTED_STATUS_SCRIPT = ROOT / ".github" / "scripts" / "trusted_status.py"

PR_NUMBER = 227
BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
RUN_ID = 8123


def _load_trusted_status() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "trusted_status_event_test", TRUSTED_STATUS_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trusted_status = _load_trusted_status()


class _FakeApi:
    def __init__(self, event: str, *, run_head_sha: str = BASE) -> None:
        self.event = event
        self.run_head_sha = run_head_sha

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/commits/{HEAD}/statuses"
        assert max_pages == 4
        return [
            {
                "id": 901,
                "context": trusted_status.TRUSTED_STATUS_CONTEXT,
                "state": "success",
                "description": trusted_status.TRUSTED_STATUS_DESCRIPTION,
                "target_url": (
                    "https://github.com/portyu9/ai-qa-automation/actions/runs/"
                    f"{RUN_ID}?pr={PR_NUMBER}&base={BASE}&head={HEAD}&merge={MERGE}"
                ),
                "creator": {
                    "login": trusted_status.TRUSTED_STATUS_BOT_LOGIN,
                    "id": trusted_status.TRUSTED_STATUS_BOT_ID,
                    "type": "Bot",
                },
            }
        ]

    def get(self, path: str) -> dict[str, Any]:
        if path == f"/pulls/{PR_NUMBER}":
            return {
                "state": "open",
                "draft": False,
                "head": {
                    "sha": HEAD,
                    "repo": {"full_name": trusted_status.EXPECTED_REPOSITORY},
                },
                "base": {
                    "sha": BASE,
                    "ref": "main",
                    "repo": {"full_name": trusted_status.EXPECTED_REPOSITORY},
                },
            }
        if path == f"/git/ref/pull/{PR_NUMBER}/merge":
            return {
                "ref": f"refs/pull/{PR_NUMBER}/merge",
                "object": {"type": "commit", "sha": MERGE},
            }
        if path == f"/git/commits/{MERGE}":
            return {
                "sha": MERGE,
                "parents": [{"sha": BASE}, {"sha": HEAD}],
            }
        if path == f"/actions/runs/{RUN_ID}":
            return {
                "id": RUN_ID,
                "name": trusted_status.EXPECTED_GATE_WORKFLOW_NAME,
                "path": trusted_status.EXPECTED_GATE_WORKFLOW_PATH,
                "event": self.event,
                "head_branch": "main",
                "head_sha": self.run_head_sha,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": trusted_status.EXPECTED_REPOSITORY},
                "head_repository": {"full_name": trusted_status.EXPECTED_REPOSITORY},
            }
        raise AssertionError(f"unexpected API path: {path}")


@pytest.mark.parametrize("event", ["workflow_run", "schedule"])
def test_trusted_status_accepts_exact_reviewed_gate_events(event: str) -> None:
    status = trusted_status.require_automatic_trusted_gate(
        _FakeApi(event),
        PR_NUMBER,
        HEAD,
        BASE,
    )
    assert status["id"] == 901


@pytest.mark.parametrize("event", ["push", "pull_request", "workflow_dispatch"])
def test_trusted_status_rejects_unreviewed_gate_events(event: str) -> None:
    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="target run is not exact-current-main gate evidence",
    ):
        trusted_status.require_automatic_trusted_gate(
            _FakeApi(event),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_scheduled_trusted_status_still_requires_exact_current_main() -> None:
    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="target run is not exact-current-main gate evidence",
    ):
        trusted_status.require_automatic_trusted_gate(
            _FakeApi("schedule", run_head_sha="d" * 40),
            PR_NUMBER,
            HEAD,
            BASE,
        )
