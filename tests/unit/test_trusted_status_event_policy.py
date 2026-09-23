from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
TRUSTED_STATUS_SCRIPT = ROOT / ".github" / "scripts" / "trusted_status.py"

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
PR_NUMBER = 321
RUN_ID = 7004
STATUS_ID = 7005


def _load_trusted_status() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "trusted_status_event_policy_test",
        TRUSTED_STATUS_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trusted_status = _load_trusted_status()


class _GateApi:
    def __init__(self, event: str) -> None:
        self.event = event

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/commits/{HEAD}/statuses"
        assert max_pages == 4
        return [
            {
                "id": STATUS_ID,
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

    def get(self, path: str) -> Any:
        if path == f"/pulls/{PR_NUMBER}":
            return {
                "number": PR_NUMBER,
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
                "head_sha": BASE,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": trusted_status.EXPECTED_REPOSITORY},
                "head_repository": {"full_name": trusted_status.EXPECTED_REPOSITORY},
            }
        raise AssertionError(f"unexpected path: {path}")


def test_default_trusted_gate_event_policy_remains_workflow_run() -> None:
    api = _GateApi("workflow_run")

    status = trusted_status.require_automatic_trusted_gate(
        api,
        PR_NUMBER,
        HEAD,
        BASE,
    )

    assert status["id"] == STATUS_ID


def test_default_trusted_gate_event_policy_rejects_schedule() -> None:
    api = _GateApi("schedule")

    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="not exact-current-main gate evidence",
    ):
        trusted_status.require_automatic_trusted_gate(
            api,
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_explicit_schedule_policy_accepts_only_schedule() -> None:
    status = trusted_status.require_automatic_trusted_gate(
        _GateApi("schedule"),
        PR_NUMBER,
        HEAD,
        BASE,
        expected_event="schedule",
    )
    assert status["id"] == STATUS_ID

    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="not exact-current-main gate evidence",
    ):
        trusted_status.require_automatic_trusted_gate(
            _GateApi("workflow_run"),
            PR_NUMBER,
            HEAD,
            BASE,
            expected_event="schedule",
        )


@pytest.mark.parametrize("event", ("workflow_dispatch", "pull_request", "push", ""))
def test_unowned_expected_event_classes_are_rejected(event: str) -> None:
    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="expected event is not code-owned",
    ):
        trusted_status.require_automatic_trusted_gate(
            _GateApi(event),
            PR_NUMBER,
            HEAD,
            BASE,
            expected_event=event,
        )
