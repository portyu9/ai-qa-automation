from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
GATE_SCRIPT = SCRIPT_DIR / "dependency_trusted_gate.py"
GOVERNANCE_SCRIPT = SCRIPT_DIR / "dependency_governance.py"
PROMOTION_SCRIPT = SCRIPT_DIR / "dependency_promotion.py"

PR_NUMBER = 228
BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
TREE = "d" * 40
RUN_ID = 99123
STATUS_ID = 4422


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


gate = _load(GATE_SCRIPT, "dependency_trusted_gate_test")
governance = _load(GOVERNANCE_SCRIPT, "dependency_governance_gate_test")
promotion = _load(PROMOTION_SCRIPT, "dependency_promotion_gate_test")


class _GateApi:
    def __init__(
        self,
        *,
        event: str = "schedule",
        run_attempt: int = 1,
        workflow_id: int = gate.TRUSTED_PR_AUTO_WORKFLOW_ID,
        workflow_name: str = gate.EXPECTED_GATE_WORKFLOW_NAME,
        workflow_path: str = gate.EXPECTED_GATE_WORKFLOW_PATH,
        live_main: str = BASE,
        merge_parent_base: str = BASE,
        merge_parent_head: str = HEAD,
        merge_tree: str = TREE,
        head_tree: str = TREE,
        status_creator_login: str = "trusted-pr-gate[bot]",
        status_creator_id: int = 322661847,
        run_id: int = RUN_ID,
    ) -> None:
        self.event = event
        self.run_attempt = run_attempt
        self.workflow_id = workflow_id
        self.workflow_name = workflow_name
        self.workflow_path = workflow_path
        self.live_main = live_main
        self.merge_parent_base = merge_parent_base
        self.merge_parent_head = merge_parent_head
        self.merge_tree = merge_tree
        self.head_tree = head_tree
        self.status_creator_login = status_creator_login
        self.status_creator_id = status_creator_id
        self.run_id = run_id

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/commits/{HEAD}/statuses"
        assert max_pages == 4
        return [
            {
                "id": STATUS_ID,
                "context": "Trusted PR Gate",
                "state": "success",
                "description": "Automatic exact-subject trusted validation passed",
                "target_url": (
                    "https://github.com/portyu9/ai-qa-automation/actions/runs/"
                    f"{RUN_ID}?pr={PR_NUMBER}&base={BASE}&head={HEAD}&merge={MERGE}"
                ),
                "creator": {
                    "login": self.status_creator_login,
                    "id": self.status_creator_id,
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
                    "repo": {"full_name": gate.EXPECTED_REPOSITORY},
                },
                "base": {
                    "sha": BASE,
                    "ref": "main",
                    "repo": {"full_name": gate.EXPECTED_REPOSITORY},
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
                "parents": [
                    {"sha": self.merge_parent_base},
                    {"sha": self.merge_parent_head},
                ],
                "tree": {"sha": self.merge_tree},
            }
        if path == f"/git/commits/{HEAD}":
            return {"sha": HEAD, "tree": {"sha": self.head_tree}}
        if path == f"/actions/runs/{RUN_ID}":
            return {
                "id": self.run_id,
                "workflow_id": self.workflow_id,
                "name": self.workflow_name,
                "path": self.workflow_path,
                "event": self.event,
                "run_attempt": self.run_attempt,
                "head_branch": "main",
                "head_sha": BASE,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": gate.EXPECTED_REPOSITORY},
                "head_repository": {"full_name": gate.EXPECTED_REPOSITORY},
            }
        if path == "/branches/main":
            return {"commit": {"sha": self.live_main}}
        raise AssertionError(f"unexpected path: {path}")


def test_dependency_gate_accepts_exact_schedule_attempt_one() -> None:
    evidence = gate.require_schedule_trusted_gate(
        _GateApi(),
        PR_NUMBER,
        HEAD,
        BASE,
    )

    assert evidence == {
        "statusId": STATUS_ID,
        "runId": RUN_ID,
        "workflowId": gate.TRUSTED_PR_AUTO_WORKFLOW_ID,
        "event": "schedule",
        "runAttempt": 1,
        "mergeSha": MERGE,
        "mergeTreeSha": TREE,
    }


def test_dependency_gate_rejects_workflow_run_even_when_shared_gate_accepts_it() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="not exact schedule-owned authority",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(event="workflow_run"),
            PR_NUMBER,
            HEAD,
            BASE,
        )


@pytest.mark.parametrize("event", ("workflow_dispatch", "pull_request", "push"))
def test_dependency_gate_rejects_unreviewed_events_at_shared_boundary(event: str) -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="target run is not exact-current-main gate evidence",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(event=event),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_rerun_attempt() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="not exact schedule-owned authority",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(run_attempt=2),
            PR_NUMBER,
            HEAD,
            BASE,
        )


@pytest.mark.parametrize(
    "kwargs",
    (
        {"workflow_id": gate.TRUSTED_PR_AUTO_WORKFLOW_ID + 1},
        {"workflow_name": "lookalike gate"},
        {"workflow_path": ".github/workflows/lookalike.yml"},
    ),
)
def test_dependency_gate_rejects_workflow_identity_drift(kwargs: dict[str, Any]) -> None:
    with pytest.raises(gate.TrustedStatusError):
        gate.require_schedule_trusted_gate(
            _GateApi(**kwargs),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_stale_current_main() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="base is not exact current main",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(live_main="e" * 40),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_wrong_merge_parents() -> None:
    with pytest.raises(gate.TrustedStatusError, match="merge parents drifted"):
        gate.require_schedule_trusted_gate(
            _GateApi(merge_parent_base="e" * 40),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_wrong_prospective_merge_tree() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="prospective merge tree differs",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(merge_tree="e" * 40),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_spoofed_non_app_status() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="status has not registered",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(
                status_creator_login="github-actions[bot]",
                status_creator_id=41898282,
            ),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_status_target_run_mismatch() -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="target run is not exact-current-main gate evidence",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(run_id=RUN_ID + 1),
            PR_NUMBER,
            HEAD,
            BASE,
        )


class _MergeApi:
    def __init__(self) -> None:
        self.events: list[str] = []

    def get(self, path: str) -> dict[str, Any]:
        assert path == f"/pulls/{PR_NUMBER}"
        self.events.append("fresh-pr")
        return {"number": PR_NUMBER}

    def put(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert path == f"/pulls/{PR_NUMBER}/merge"
        assert payload == {"sha": HEAD, "merge_method": "merge"}
        self.events.append("merge")
        return {"merged": True, "sha": MERGE}


def test_dependency_governance_revalidates_gate_after_fresh_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _MergeApi()
    subject = {"number": PR_NUMBER, "headSha": HEAD, "baseSha": BASE}
    config = {"mergeMethod": "merge"}

    def assess(
        api_arg: Any,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> dict[str, Any]:
        assert api_arg is api
        assert pr == {"number": PR_NUMBER}
        assert config_arg is config
        assert require_checks is False
        api.events.append("rebind")
        return subject

    def require_gate(api_arg: Any, number: int, head: str, base: str) -> dict[str, Any]:
        assert api_arg is api
        assert (number, head, base) == (PR_NUMBER, HEAD, BASE)
        api.events.append("gate")
        return {"runId": RUN_ID}

    def finalize(
        api_arg: Any,
        result: dict[str, Any],
        subject_arg: dict[str, Any],
        config_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is api
        assert result == {"merged": True, "sha": MERGE}
        assert subject_arg is subject
        assert config_arg is config
        api.events.append("finalize")
        return {"mergeSha": MERGE}

    monkeypatch.setattr(governance, "assess", assess)
    monkeypatch.setattr(governance, "require_schedule_trusted_gate", require_gate)
    monkeypatch.setattr(governance, "finalize_post_merge_evidence", finalize)

    assert governance._merge(api, subject, config) == {"mergeSha": MERGE}
    assert api.events == ["fresh-pr", "rebind", "gate", "merge", "finalize"]


def test_dependency_promotion_revalidates_gate_after_fresh_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _MergeApi()
    promoted = {"number": PR_NUMBER, "headSha": HEAD, "baseSha": BASE}
    config = {"mergeMethod": "merge"}

    def validate(
        api_arg: Any,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert api_arg is api
        assert pr == {"number": PR_NUMBER}
        assert config_arg is config
        assert require_checks is False
        api.events.append("rebind")
        return {"source": True}, promoted

    def require_gate(api_arg: Any, number: int, head: str, base: str) -> dict[str, Any]:
        assert api_arg is api
        assert (number, head, base) == (PR_NUMBER, HEAD, BASE)
        api.events.append("gate")
        return {"runId": RUN_ID}

    def finalize(
        api_arg: Any,
        result: dict[str, Any],
        subject_arg: dict[str, Any],
        config_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is api
        assert result == {"merged": True, "sha": MERGE}
        assert subject_arg is promoted
        assert config_arg is config
        api.events.append("finalize")
        return {"mergeSha": MERGE}

    monkeypatch.setattr(promotion, "_validate_promotion", validate)
    monkeypatch.setattr(promotion, "require_schedule_trusted_gate", require_gate)
    monkeypatch.setattr(promotion, "finalize_post_merge_evidence", finalize)

    assert promotion._publish_and_merge(api, promoted, config) == {"mergeSha": MERGE}
    assert api.events == ["fresh-pr", "rebind", "gate", "merge", "finalize"]
