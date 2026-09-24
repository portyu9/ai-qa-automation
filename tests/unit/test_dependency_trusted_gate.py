from __future__ import annotations

import importlib.util
import os
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
GOVERNANCE_WORKFLOW = ROOT / ".github" / "workflows" / "dependency-governance.yml"

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
        target_base: str = BASE,
        target_head: str = HEAD,
        target_merge: str = MERGE,
        merge_ref_sha: str = MERGE,
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
        self.target_base = target_base
        self.target_head = target_head
        self.target_merge = target_merge
        self.merge_ref_sha = merge_ref_sha

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
                    f"{RUN_ID}?pr={PR_NUMBER}&base={self.target_base}"
                    f"&head={self.target_head}&merge={self.target_merge}"
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
                "object": {"type": "commit", "sha": self.merge_ref_sha},
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


@pytest.mark.parametrize("attempt", (2, True))
def test_dependency_gate_rejects_rerun_or_noninteger_attempt(attempt: Any) -> None:
    with pytest.raises(gate.TrustedStatusError):
        gate.require_schedule_trusted_gate(
            _GateApi(run_attempt=attempt),
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


@pytest.mark.parametrize(
    "kwargs",
    (
        {"target_base": "e" * 40},
        {"target_head": "e" * 40},
    ),
)
def test_dependency_gate_rejects_stale_status_subject_binding(
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(
        gate.TrustedStatusError,
        match="status is bound to a stale subject",
    ):
        gate.require_schedule_trusted_gate(
            _GateApi(**kwargs),
            PR_NUMBER,
            HEAD,
            BASE,
        )


def test_dependency_gate_rejects_moved_merge_ref() -> None:
    with pytest.raises(gate.TrustedStatusError, match="merge ref drifted"):
        gate.require_schedule_trusted_gate(
            _GateApi(merge_ref_sha="e" * 40),
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


def test_dependency_governance_moved_subject_stops_before_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _MergeApi()
    subject = {"number": PR_NUMBER, "headSha": HEAD, "baseSha": BASE}
    moved = {"number": PR_NUMBER, "headSha": "e" * 40, "baseSha": BASE}
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
        return moved

    def forbidden_gate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("gate must not be consulted for moved subject")

    monkeypatch.setattr(governance, "assess", assess)
    monkeypatch.setattr(governance, "require_schedule_trusted_gate", forbidden_gate)

    with pytest.raises(governance.PolicyBlock, match="changed before merge"):
        governance._merge(api, subject, config)
    assert api.events == ["fresh-pr", "rebind"]


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


def test_dependency_promotion_moved_subject_stops_before_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _MergeApi()
    promoted = {"number": PR_NUMBER, "headSha": HEAD, "baseSha": BASE}
    moved = {"number": PR_NUMBER, "headSha": "e" * 40, "baseSha": BASE}
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
        return {"source": True}, moved

    def forbidden_gate(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("gate must not be consulted for moved promotion")

    monkeypatch.setattr(promotion, "_validate_promotion", validate)
    monkeypatch.setattr(promotion, "require_schedule_trusted_gate", forbidden_gate)

    with pytest.raises(promotion.PolicyBlock, match="changed before guarded merge"):
        promotion._publish_and_merge(api, promoted, config)
    assert api.events == ["fresh-pr", "rebind"]


def test_dependency_governance_reconcile_stops_after_successful_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_gets: list[str] = []

    class _Api:
        def get(self, path: str) -> dict[str, Any]:
            observed_gets.append(path)
            if path == "/pulls/601":
                return {"number": 601, "head": {"ref": "feature/dependabot"}}
            raise AssertionError(f"governance continued after merge: {path}")

    api = _Api()
    config = {
        "repository": gate.EXPECTED_REPOSITORY,
        "automergeEnabled": True,
    }
    monkeypatch.setenv("GITHUB_REPOSITORY", gate.EXPECTED_REPOSITORY)
    monkeypatch.setattr(governance, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(
        governance,
        "open_dependabot_prs",
        lambda api_arg: [{"number": 601}, {"number": 602}],
    )

    subject = {"number": 601, "headSha": HEAD, "baseSha": BASE}

    def assess(
        api_arg: object,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> dict[str, Any]:
        assert api_arg is api
        assert pr["number"] == 601
        assert config_arg is config
        assert require_checks is True
        return subject

    monkeypatch.setattr(governance, "assess", assess)
    monkeypatch.setattr(
        governance,
        "_merge",
        lambda api_arg, subject_arg, config_arg: {"mergeSha": MERGE},
    )

    assert governance.reconcile(config, allow_merge=True) == 1
    assert observed_gets == ["/pulls/601"]


def test_dependency_promotion_reconcile_stops_after_successful_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_gets: list[str] = []

    class _Api:
        def get(self, path: str) -> dict[str, Any]:
            observed_gets.append(path)
            if path == "/pulls/701":
                return {"number": 701}
            raise AssertionError(f"promotion continued after merge: {path}")

    api = _Api()
    config = {
        "repository": gate.EXPECTED_REPOSITORY,
        "automergeEnabled": True,
    }
    monkeypatch.setenv("GITHUB_REPOSITORY", gate.EXPECTED_REPOSITORY)
    monkeypatch.setattr(promotion, "GitHubApi", lambda token, repository: api)
    monkeypatch.setattr(promotion, "_prune_orphan_promotion_refs", lambda api_arg: 0)
    monkeypatch.setattr(
        promotion,
        "_promotion_pulls",
        lambda api_arg: [
            {"number": 701, "head": {"ref": "automation/dependency-promotion-1-aaaaaaaaaaaa"}},
            {"number": 702, "head": {"ref": "automation/dependency-promotion-2-bbbbbbbbbbbb"}},
        ],
    )

    promoted = {"number": 701, "headSha": HEAD, "baseSha": BASE}

    def validate(
        api_arg: object,
        pr: dict[str, Any],
        config_arg: dict[str, Any],
        *,
        require_checks: bool,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        assert api_arg is api
        assert pr == {"number": 701}
        assert config_arg is config
        assert require_checks is False
        return {"source": True}, promoted

    monkeypatch.setattr(promotion, "_validate_promotion", validate)
    monkeypatch.setattr(
        promotion,
        "_publish_and_merge",
        lambda api_arg, promotion_arg, config_arg: {"mergeSha": MERGE},
    )

    assert promotion.reconcile(config, allow_merge=True) == 0
    assert observed_gets == ["/pulls/701"]


def test_dependency_promotion_merge_signal_is_exact_owned_github_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "github-output"
    output.write_bytes(b"")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    promotion._publish_merge_signal(output)
    assert output.read_bytes() == b"merged=true\n"

    wrong = tmp_path / "wrong-output"
    wrong.write_bytes(b"")
    with pytest.raises(promotion.GovernanceError, match="exact GitHub Actions output"):
        promotion._publish_merge_signal(wrong)
    assert wrong.read_bytes() == b""


def test_dependency_workflow_skips_action_governance_after_promotion_merge() -> None:
    workflow = GOVERNANCE_WORKFLOW.read_text(encoding="utf-8")
    assert "id: python_promotion" in workflow
    assert '--github-output "$GITHUB_OUTPUT"' in workflow
    assert "if: steps.python_promotion.outputs.merged != 'true'" in workflow

def _post_merge_ci_row(
    *,
    run_id: int = 88001,
    workflow_id: int = governance.POST_MERGE_CI_WORKFLOW_ID,
    run_attempt: int = 1,
    name: str = governance.POST_MERGE_CI_NAME,
    path: str = governance.POST_MERGE_CI_PATH,
    head_branch: str = "main",
    head_sha: str = MERGE,
    event: str = "push",
    status: str = "queued",
    conclusion: str | None = None,
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": workflow_id,
        "run_attempt": run_attempt,
        "name": name,
        "path": path,
        "head_branch": head_branch,
        "head_sha": head_sha,
        "event": event,
        "status": status,
        "conclusion": conclusion,
    }


def test_post_merge_ci_selector_requires_exact_attempt_one_identity() -> None:
    canonical = _post_merge_ci_row()
    assert governance._select_post_merge_ci_run([canonical], MERGE) == canonical

    for row, message in (
        ({**canonical, "workflow_id": 1}, "mismatched workflow identity"),
        ({**canonical, "name": "lookalike"}, "mismatched workflow identity"),
        ({**canonical, "path": ".github/workflows/lookalike.yml"}, "mismatched workflow identity"),
        ({**canonical, "head_sha": "e" * 40}, "different head SHA"),
        ({**canonical, "head_branch": "other"}, "not bound to main"),
        ({**canonical, "event": "pull_request"}, "unexpected event"),
        ({**canonical, "run_attempt": 2}, "run_attempt must equal 1"),
        (
            {**canonical, "status": "completed", "conclusion": "failure"},
            "completed non-successfully",
        ),
    ):
        with pytest.raises(governance.GovernanceError, match=message):
            governance._select_post_merge_ci_run([row], MERGE)

    with pytest.raises(governance.GovernanceError, match="ambiguous exact-subject CI evidence"):
        governance._select_post_merge_ci_run(
            [canonical, {**canonical, "id": 88002}],
            MERGE,
        )


class _PostMergeCiApi:
    def __init__(
        self,
        *,
        existing: dict[str, Any] | None = None,
        registered: dict[str, Any] | None = None,
        move_main_after_registration: bool = False,
    ) -> None:
        self.existing = existing
        self.registered = registered
        self.move_main_after_registration = move_main_after_registration
        self.dispatched = False
        self.main_reads = 0
        self.posts: list[tuple[str, dict[str, Any] | None]] = []

    def get(self, path: str) -> Any:
        if path == "/branches/main":
            self.main_reads += 1
            observed = (
                "f" * 40
                if self.move_main_after_registration and self.dispatched and self.main_reads >= 2
                else MERGE
            )
            return {"commit": {"sha": observed}}
        raise governance.GovernanceError(f"unexpected post-merge CI GET path: {path}")

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/actions/runs?head_sha={MERGE}"
        assert max_pages == 2
        if self.existing is not None:
            return [self.existing]
        if self.dispatched and self.registered is not None:
            return [self.registered]
        return []

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        assert token is None
        self.posts.append((path, payload))
        self.dispatched = True
        return None


def test_post_merge_ci_liveness_reuses_existing_exact_run() -> None:
    existing = _post_merge_ci_row(
        status="completed",
        conclusion="success",
    )
    api = _PostMergeCiApi(existing=existing)
    evidence = governance._ensure_post_merge_ci(api, MERGE, {"baseBranch": "main"})

    assert api.posts == []
    assert evidence == {
        "postMergeCiWorkflowId": governance.POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": 88001,
        "postMergeCiRunAttempt": 1,
        "postMergeCiEvent": "push",
        "postMergeCiStatus": "completed",
        "postMergeCiDispatched": False,
    }


def test_post_merge_ci_liveness_dispatches_exact_main_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registered = _post_merge_ci_row(
        run_id=88003,
        event="workflow_dispatch",
        status="queued",
    )
    api = _PostMergeCiApi(registered=registered)
    monkeypatch.setattr(governance.time, "sleep", lambda _seconds: None)

    evidence = governance._ensure_post_merge_ci(api, MERGE, {"baseBranch": "main"})

    assert api.posts == [
        (
            "/actions/workflows/ci.yml/dispatches",
            {
                "ref": "main",
                "inputs": {"subject_sha": MERGE, "subject_ref": "main"},
            },
        )
    ]
    assert evidence == {
        "postMergeCiWorkflowId": governance.POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": 88003,
        "postMergeCiRunAttempt": 1,
        "postMergeCiEvent": "workflow_dispatch",
        "postMergeCiStatus": "queued",
        "postMergeCiDispatched": True,
    }


def test_post_merge_ci_liveness_fails_closed_on_registration_and_main_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(governance.time, "sleep", lambda _seconds: None)

    absent = _PostMergeCiApi()
    with pytest.raises(
        governance.GovernanceError,
        match="explicit CI dispatch did not register",
    ):
        governance._ensure_post_merge_ci(absent, MERGE, {"baseBranch": "main"})

    wrong_event = _PostMergeCiApi(
        registered=_post_merge_ci_row(run_id=88004, event="push"),
    )
    with pytest.raises(
        governance.GovernanceError,
        match="unexpected event after explicit dispatch",
    ):
        governance._ensure_post_merge_ci(wrong_event, MERGE, {"baseBranch": "main"})

    moved = _PostMergeCiApi(
        registered=_post_merge_ci_row(
            run_id=88005,
            event="workflow_dispatch",
        ),
        move_main_after_registration=True,
    )
    with pytest.raises(
        governance.GovernanceError,
        match="current main changed after post-merge CI registration",
    ):
        governance._ensure_post_merge_ci(moved, MERGE, {"baseBranch": "main"})


def test_finalize_post_merge_evidence_requires_ci_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject = {"baseSha": BASE, "headSha": HEAD}
    config = {"baseBranch": "main"}
    api = object()
    calls: list[str] = []

    def verify(
        api_arg: object,
        result: dict[str, Any],
        subject_arg: dict[str, Any],
        config_arg: dict[str, Any],
    ) -> tuple[str, str]:
        assert api_arg is api
        assert result == {"sha": MERGE}
        assert subject_arg is subject
        assert config_arg is config
        calls.append("verify")
        return MERGE, TREE

    def ensure(
        api_arg: object,
        subject_sha: str,
        config_arg: dict[str, Any],
    ) -> dict[str, Any]:
        assert api_arg is api
        assert subject_sha == MERGE
        assert config_arg is config
        calls.append("ci")
        return {
            "postMergeCiWorkflowId": governance.POST_MERGE_CI_WORKFLOW_ID,
            "postMergeCiRunId": 88006,
            "postMergeCiRunAttempt": 1,
            "postMergeCiEvent": "push",
            "postMergeCiStatus": "queued",
            "postMergeCiDispatched": False,
        }

    monkeypatch.setattr(governance, "_verify_actual_merge_commit", verify)
    monkeypatch.setattr(governance, "_ensure_post_merge_ci", ensure)

    evidence = governance.finalize_post_merge_evidence(
        api,
        {"sha": MERGE},
        subject,
        config,
    )

    assert calls == ["verify", "ci"]
    assert evidence == {
        "mergeSha": MERGE,
        "sourceTreeSha": TREE,
        "postMergeBinding": (
            "exact-current-main-parents-validated-source-tree-and-ci-registration"
        ),
        "postMergeCiWorkflowId": governance.POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": 88006,
        "postMergeCiRunAttempt": 1,
        "postMergeCiEvent": "push",
        "postMergeCiStatus": "queued",
        "postMergeCiDispatched": False,
    }

