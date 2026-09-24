from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
AUTOHEAL_SCRIPT = SCRIPT_DIR / "security_autoheal.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "security_autoheal_routing_integration_test",
        AUTOHEAL_SCRIPT,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load()
MAIN = "a" * 40
RUN_ID = 12345
RUN_ATTEMPT = 2
ARTIFACT_ID = 98765
ARTIFACT_DIGEST = "sha256:" + ("d" * 64)


def _alert(
    *,
    number: int = 7,
    rule: str = "py/reflective-xss",
    path: str = "examples/reference_sut/app.py",
    severity: str = "8.0",
) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {"id": rule, "security_severity": severity},
        "most_recent_instance": {
            "state": "open",
            "ref": "refs/heads/main",
            "commit_sha": MAIN,
            "location": {
                "path": path,
                "start_line": 10,
                "end_line": 10,
                "start_column": 1,
                "end_column": 5,
            },
            "message": {"text": "security finding"},
        },
    }


class _PlanApi:
    def __init__(
        self,
        alert: dict[str, Any],
        *,
        autofix_status: int = 404,
        autofix_state: str | None = None,
    ) -> None:
        self.alert = alert
        self.autofix_status = autofix_status
        self.autofix_state = autofix_state
        self.request_calls: list[tuple[str, str]] = []

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            return {"commit": {"sha": MAIN}}
        raise AssertionError(path)

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        if path == "/pulls?state=closed&sort=updated&direction=desc":
            assert max_pages == 10
            return []
        if path.startswith("/code-scanning/alerts?"):
            assert max_pages == 10
            return [self.alert]
        raise AssertionError(path)

    def request_status(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        assert payload is None
        assert token is None
        self.request_calls.append((method, path))
        response: dict[str, Any] = {}
        if self.autofix_state is not None:
            response["status"] = self.autofix_state
        return self.autofix_status, response


class _ArtifactApi(_PlanApi):
    def __init__(
        self,
        alert: dict[str, Any],
        *,
        run_status: str = "in_progress",
        run_conclusion: str | None = None,
    ) -> None:
        super().__init__(alert)
        self.run_status = run_status
        self.run_conclusion = run_conclusion

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            return {"commit": {"sha": MAIN}}
        if path == f"/actions/artifacts/{ARTIFACT_ID}":
            return {
                "id": ARTIFACT_ID,
                "name": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
                "expired": False,
                "digest": ARTIFACT_DIGEST,
                "size_in_bytes": 2048,
                "workflow_run": {
                    "id": RUN_ID,
                    "head_sha": MAIN,
                    "head_branch": "main",
                },
            }
        if path == f"/actions/runs/{RUN_ID}":
            return {
                "id": RUN_ID,
                "workflow_id": autoheal.SECURITY_AUTOHEAL_WORKFLOW_ID,
                "path": autoheal.SECURITY_AUTOHEAL_WORKFLOW_PATH,
                "run_attempt": RUN_ATTEMPT,
                "event": "schedule",
                "head_branch": "main",
                "head_sha": MAIN,
                "status": self.run_status,
                "conclusion": self.run_conclusion,
            }
        raise AssertionError(path)


def _config() -> dict[str, Any]:
    return autoheal.load_config()


@pytest.fixture(autouse=True)
def _run_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "portyu9/ai-qa-automation")
    monkeypatch.setenv("GITHUB_RUN_ID", str(RUN_ID))
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", str(RUN_ATTEMPT))


def test_deterministic_route_plan_never_queries_autofix() -> None:
    api = _PlanApi(_alert())

    plan = autoheal._build_route_plan(api, _config(), MAIN)

    assert api.request_calls == []
    assert plan["mainSha"] == MAIN
    assert plan["workflowRunId"] == RUN_ID
    assert plan["workflowRunAttempt"] == RUN_ATTEMPT
    assert len(plan["records"]) == 1
    record = plan["records"][0]
    assert record["decision"] == "ordinary-deterministic-autoheal"
    assert record["strategy"] == autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    assert autoheal._canonical_route_plan(plan).endswith(b"\n")


def test_model_route_planning_uses_get_only_and_blocks_without_live_evidence() -> None:
    alert = _alert(
        rule="py/incomplete-url-substring-sanitization",
        path="src/ai_qa_automation/example.py",
    )
    api = _PlanApi(alert, autofix_status=404)

    plan = autoheal._build_route_plan(api, _config(), MAIN)

    assert api.request_calls == [
        ("GET", "/code-scanning/alerts/7/autofix"),
    ]
    record = plan["records"][0]
    assert record["decision"] == "blocked-external-evidence"
    assert record["strategy"] == autoheal.MODEL_AUTOFIX_STRATEGY
    assert record["autofixEligibility"] == "unknown"


def test_route_plan_digest_rejects_tampering() -> None:
    plan = autoheal._build_route_plan(_PlanApi(_alert()), _config(), MAIN)
    plan["mainSha"] = "b" * 40

    with pytest.raises(autoheal.AutohealError, match="digest does not match"):
        autoheal._canonical_route_plan(plan)


def test_route_plan_persistence_is_runner_temp_bound_and_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    plan = autoheal._build_route_plan(_PlanApi(_alert()), _config(), MAIN)
    target = autoheal._route_plan_output_path()

    autoheal._write_route_plan(target, plan)

    assert target.read_bytes() == autoheal._canonical_route_plan(plan)
    assert target.stat().st_mode & 0o077 == 0
    assert target.parent.stat().st_mode & 0o077 == 0


def test_route_plan_persistence_rejects_workspace_or_preexisting_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    plan = autoheal._build_route_plan(_PlanApi(_alert()), _config(), MAIN)

    with pytest.raises(autoheal.AutohealError, match="exact runner-owned temp path"):
        autoheal._write_route_plan(tmp_path / "workspace-plan.json", plan)

    redirect = tmp_path / "redirect"
    redirect.mkdir(mode=0o700)
    autoheal._route_plan_output_path().parent.symlink_to(redirect, target_is_directory=True)
    with pytest.raises(autoheal.AutohealError, match="directory already exists"):
        autoheal._write_route_plan(autoheal._route_plan_output_path(), plan)


def test_route_plan_loading_rejects_non_runner_temp_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    with pytest.raises(autoheal.AutohealError, match="exact runner-owned temp path"):
        autoheal._load_route_plan(tmp_path / "alternate-route-plan.json", _config())


def test_route_plan_rebind_requires_identical_live_routing_truth() -> None:
    api = _PlanApi(_alert())
    plan = autoheal._build_route_plan(api, _config(), MAIN)

    rebound = autoheal._rebind_route_plan(api, plan, _config())
    assert set(rebound) == {7}
    assert rebound[7] == plan["records"][0]

    drifted = _PlanApi(_alert(severity="9.0"))
    with pytest.raises(autoheal.AutohealError, match="routing truth drifted"):
        autoheal._rebind_route_plan(drifted, plan, _config())


def test_route_artifact_must_bind_exact_in_progress_controller_run() -> None:
    api = _ArtifactApi(_alert())
    plan = autoheal._build_route_plan(api, _config(), MAIN)

    evidence = autoheal._require_route_plan_artifact(
        api,
        plan,
        artifact_id=ARTIFACT_ID,
        artifact_name=f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
        artifact_digest=ARTIFACT_DIGEST,
    )
    assert evidence["routePlanDigest"] == plan["planDigest"]
    assert evidence["routeArtifactId"] == ARTIFACT_ID

    completed = _ArtifactApi(_alert(), run_status="completed", run_conclusion="success")
    with pytest.raises(autoheal.AutohealError, match="in-progress controller authority"):
        autoheal._require_route_plan_artifact(
            completed,
            plan,
            artifact_id=ARTIFACT_ID,
            artifact_name=f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
            artifact_digest=ARTIFACT_DIGEST,
        )


def test_route_bound_marker_requires_successful_originating_controller_run() -> None:
    api = _ArtifactApi(_alert(), run_status="completed", run_conclusion="success")
    plan = autoheal._build_route_plan(api, _config(), MAIN)
    record = plan["records"][0]
    metadata = {
        "routePlanDigest": plan["planDigest"],
        "routePlanRunId": RUN_ID,
        "routePlanRunAttempt": RUN_ATTEMPT,
        "routeArtifactId": ARTIFACT_ID,
        "routeArtifactName": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
        "routeArtifactDigest": ARTIFACT_DIGEST,
    }

    autoheal._require_marker_route_artifact(api, metadata, MAIN)

    failed = _ArtifactApi(_alert(), run_status="completed", run_conclusion="failure")
    with pytest.raises(autoheal.PolicyBlock, match="successful controller-run authority"):
        autoheal._require_marker_route_artifact(failed, metadata, MAIN)

    assert record["decision"] == "ordinary-deterministic-autoheal"


def test_generated_repair_discovery_rejects_stripped_marker() -> None:
    stripped = {
        "number": 99,
        "user": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "head": {
            "ref": "automation/codeql-autoheal-7-" + "a" * 64 + "-a1",
        },
        "body": "marker removed",
    }

    with pytest.raises(
        autoheal.PolicyBlock,
        match="missing or malformed provenance marker",
    ):
        autoheal._generated_repairs([stripped])


def test_repair_admission_rejects_route_provenance_stripping() -> None:
    class _Api:
        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            assert path.startswith("/code-scanning/alerts?")
            assert max_pages == 10
            return [_alert()]

    metadata = {
        "alert": 7,
        "attempt": 1,
        "generator": "deterministic",
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }

    with pytest.raises(autoheal.PolicyBlock, match="lacks persisted route provenance"):
        autoheal._rebind_repair_alert(
            _Api(),
            metadata,
            {"baseSha": MAIN},
            _config(),
        )


def test_generated_repair_commit_route_binding_is_immutable_and_unambiguous() -> None:
    digest = "f" * 64
    plan_digest = "e" * 64
    message = autoheal._route_bound_commit_message(7, digest, plan_digest)
    payload = {"commit": {"message": message}}

    assert autoheal._generated_commit_route_digest(payload) == digest
    assert autoheal._generated_commit_plan_digest(payload) == plan_digest
    assert (
        autoheal._generated_commit_route_digest(
            {
                "commit": {
                    "message": (
                        message
                        + "\n"
                        + autoheal.ROUTE_RECORD_TRAILER_PREFIX
                        + ("e" * 64)
                    )
                }
            }
        )
        is None
    )
    assert (
        autoheal._generated_commit_route_digest(
            {"commit": {"message": "security: auto-heal CodeQL alert #7"}}
        )
        is None
    )
    assert (
        autoheal._generated_commit_plan_digest(
            {"commit": {"message": "security: auto-heal CodeQL alert #7"}}
        )
        is None
    )
    assert (
        autoheal._generated_commit_plan_digest(
            {
                "commit": {
                    "message": (
                        message
                        + "\n"
                        + autoheal.ROUTE_PLAN_TRAILER_PREFIX
                        + ("a" * 64)
                    )
                }
            }
        )
        is None
    )


def test_generated_pr_marker_binds_route_and_artifact_provenance() -> None:
    plan_api = _PlanApi(_alert())
    plan = autoheal._build_route_plan(plan_api, _config(), MAIN)
    record = plan["records"][0]
    subject = autoheal._subject_from_route(record)
    route_evidence = {
        "routePlanDigest": plan["planDigest"],
        "routePlanRunId": RUN_ID,
        "routePlanRunAttempt": RUN_ATTEMPT,
        "routeArtifactId": ARTIFACT_ID,
        "routeArtifactName": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
        "routeArtifactDigest": ARTIFACT_DIGEST,
    }

    class _PrApi:
        body: str | None = None

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": MAIN}}

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            assert path == "/pulls"
            self.body = payload["body"]
            return {"number": 99, "head": {"sha": "b" * 40}}

    api = _PrApi()
    number = autoheal._create_pull_request(
        api,
        "automation/codeql-autoheal-7-" + record["fingerprint"] + "-a1",
        "b" * 40,
        subject,
        1,
        deterministic=True,
        strategy=record["strategy"],
        route_record=record,
        route_evidence=route_evidence,
    )

    assert number == 99
    marker = autoheal._parse_marker(api.body)
    assert marker is not None
    assert marker["routeRecordDigest"] == record["recordDigest"]
    assert marker["routePlanDigest"] == plan["planDigest"]
    assert marker["routeArtifactId"] == ARTIFACT_ID
    assert marker["routeDecision"] == "ordinary-deterministic-autoheal"


def test_generated_pr_publication_rejects_main_drift() -> None:
    plan = autoheal._build_route_plan(_PlanApi(_alert()), _config(), MAIN)
    record = plan["records"][0]
    subject = autoheal._subject_from_route(record)
    route_evidence = {
        "routePlanDigest": plan["planDigest"],
        "routePlanRunId": RUN_ID,
        "routePlanRunAttempt": RUN_ATTEMPT,
        "routeArtifactId": ARTIFACT_ID,
        "routeArtifactName": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
        "routeArtifactDigest": ARTIFACT_DIGEST,
    }

    class _DriftApi:
        posts = 0

        def get(self, path: str) -> dict[str, Any]:
            assert path == "/branches/main"
            return {"commit": {"sha": "b" * 40}}

        def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
            self.posts += 1
            raise AssertionError("stale subject must not publish a pull request")

    api = _DriftApi()
    with pytest.raises(
        autoheal.PolicyBlock, match="main advanced before route-authorized repair PR"
    ):
        autoheal._create_pull_request(
            api,
            "automation/codeql-autoheal-7-" + record["fingerprint"] + "-a1",
            "c" * 40,
            subject,
            1,
            deterministic=True,
            strategy=record["strategy"],
            route_record=record,
            route_evidence=route_evidence,
        )
    assert api.posts == 0


def test_reconcile_stops_after_first_route_authorized_repair_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    alerts = [_alert(number=7), _alert(number=8)]
    records = {
        int(alert["number"]): autoheal.route_security_alert(
            alert,
            main_sha=MAIN,
            config=config,
            attempts_by_strategy={
                autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY: 0,
            },
            autofix_eligibility="unknown",
        )
        for alert in alerts
    }
    route_plan = {
        "mainSha": MAIN,
        "planDigest": "e" * 64,
        "workflowRunId": RUN_ID,
        "workflowRunAttempt": RUN_ATTEMPT,
    }
    route_evidence = {
        "routePlanDigest": route_plan["planDigest"],
        "routePlanRunId": RUN_ID,
        "routePlanRunAttempt": RUN_ATTEMPT,
        "routeArtifactId": ARTIFACT_ID,
        "routeArtifactName": f"{autoheal.ROUTE_PLAN_ARTIFACT_PREFIX}-{RUN_ID}-{RUN_ATTEMPT}",
        "routeArtifactDigest": ARTIFACT_DIGEST,
    }

    class _Api:
        def __init__(self, token: str, repository: str) -> None:
            assert repository == config["repository"]

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            assert path.startswith("/code-scanning/alerts?")
            assert max_pages == 10
            return alerts

    created: list[int] = []
    monkeypatch.setattr(autoheal, "GitHubApi", _Api)
    monkeypatch.setattr(autoheal, "_current_main", lambda api, cfg: MAIN)
    monkeypatch.setattr(autoheal, "_load_route_plan", lambda path, cfg: route_plan)
    monkeypatch.setattr(
        autoheal,
        "_require_route_plan_artifact",
        lambda *args, **kwargs: route_evidence,
    )
    monkeypatch.setattr(autoheal, "_rebind_route_plan", lambda api, plan, cfg: records)
    monkeypatch.setattr(autoheal, "_reconcile_terminal_closure", lambda *args: False)
    monkeypatch.setattr(autoheal, "_open_pulls", lambda api: [])
    monkeypatch.setattr(autoheal, "_generated_repairs", lambda pulls: [])
    monkeypatch.setattr(autoheal, "_recoverable_model_autofix_branches", lambda *args: set())
    monkeypatch.setattr(autoheal, "_prune_orphan_repair_refs", lambda *args, **kwargs: None)

    def create_repair(api: Any, subject: dict[str, Any], cfg: dict[str, Any], **kwargs: Any) -> int:
        created.append(int(subject["number"]))
        return 900 + int(subject["number"])

    monkeypatch.setattr(autoheal, "_create_repair", create_repair)

    result = autoheal.reconcile(
        config,
        allow_merge=True,
        route_plan_path=Path("route-plan.json"),
        route_artifact_id=ARTIFACT_ID,
        route_artifact_name=route_evidence["routeArtifactName"],
        route_artifact_digest=ARTIFACT_DIGEST,
    )

    assert result == 1
    assert created == [7]


def test_workflow_persists_route_plan_before_live_reconcile() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security-autoheal.yml").read_text(
        encoding="utf-8"
    )

    plan = workflow.index("Plan exact-main deterministic security routes")
    upload = workflow.index("Persist exact-run route plan before mutation")
    restore = workflow.index("Restore exact-run route plan from prior read-only job")
    reconcile = workflow.index("Reconcile exact-subject CodeQL remediations from persisted routes")

    assert plan < upload < restore < reconcile
    assert "name: plan-codeql-autoheal-routes" in workflow
    assert "needs: route-plan" in workflow
    assert "actions: read" in workflow
    assert "pull-requests: read" in workflow
    assert "security-events: read" in workflow
    assert "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8" in workflow
    assert "artifact-ids: ${{ needs.route-plan.outputs.artifact-id }}" in workflow
    assert "--route-artifact-id ${{ needs.route-plan.outputs.artifact-id }}" in workflow
    assert (
        "--route-artifact-digest sha256:${{ needs.route-plan.outputs.artifact-digest }}" in workflow
    )
    assert '"$RUNNER_TEMP/security-autoheal-route-plan/route-plan.json"' in workflow\n    assert "${{ runner.temp }}/security-autoheal-route-plan" in workflow\n    assert ".github/scripts/security_alert_routing.py" in workflow

    route_job = workflow[workflow.index("  route-plan:") : workflow.index("\n  reconcile:")]
    assert ": write" not in route_job


class _IntentApi:
    def __init__(
        self,
        record: dict[str, Any],
        *,
        existing: list[dict[str, Any]] | None = None,
        move_main_after_post: bool = False,
    ) -> None:
        self.record = record
        self.existing = list(existing or [])
        self.move_main_after_post = move_main_after_post
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.main_reads = 0

    def get(self, path: str) -> dict[str, Any]:
        if path == "/branches/main":
            self.main_reads += 1
            sha = (
                "b" * 40
                if self.move_main_after_post and self.posts
                else str(self.record["baseSha"])
            )
            return {"commit": {"sha": sha}}
        raise AssertionError(path)

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        name, _, _ = autoheal._autofix_intent_identity(self.record)
        encoded = autoheal.urllib.parse.quote(name, safe="")
        assert path == (
            f"/commits/{self.record['baseSha']}/check-runs?filter=all&check_name={encoded}"
        )
        assert max_pages == 2
        return list(self.existing)

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert path == "/check-runs"
        self.posts.append((path, payload))
        return {
            "id": 4242,
            "name": payload["name"],
            "external_id": payload["external_id"],
            "head_sha": payload["head_sha"],
            "status": "completed",
            "conclusion": "neutral",
            "app": {
                "id": autoheal.GITHUB_ACTIONS_APP_ID,
                "slug": autoheal.GITHUB_ACTIONS_APP_SLUG,
            },
        }


def _model_unknown_record() -> dict[str, Any]:
    alert = _alert(
        rule="py/incomplete-url-substring-sanitization",
        path="src/ai_qa_automation/example.py",
    )
    plan = autoheal._build_route_plan(
        _PlanApi(alert, autofix_status=404),
        _config(),
        MAIN,
    )
    record = plan["records"][0]
    assert record["decision"] == "blocked-external-evidence"
    assert record["autofixEligibility"] == "unknown"
    return record


def test_autofix_submission_intent_is_persisted_before_provider_authority() -> None:
    record = _model_unknown_record()
    api = _IntentApi(record)

    assert autoheal._ensure_autofix_submission_intent(api, record, _config()) is True
    assert len(api.posts) == 1
    payload = api.posts[0][1]
    assert payload["head_sha"] == MAIN
    assert payload["status"] == "completed"
    assert payload["conclusion"] == "neutral"
    assert payload["name"].startswith(autoheal.AUTOFIX_INTENT_CHECK_PREFIX)
    assert payload["external_id"].startswith("aiqa-autofix-intent:")


def test_existing_exact_autofix_intent_suppresses_provider_replay() -> None:
    record = _model_unknown_record()
    name, external_id, _ = autoheal._autofix_intent_identity(record)
    existing = {
        "id": 77,
        "name": name,
        "external_id": external_id,
        "head_sha": MAIN,
        "status": "completed",
        "conclusion": "neutral",
        "app": {
            "id": autoheal.GITHUB_ACTIONS_APP_ID,
            "slug": autoheal.GITHUB_ACTIONS_APP_SLUG,
        },
    }
    api = _IntentApi(record, existing=[existing])

    assert autoheal._ensure_autofix_submission_intent(api, record, _config()) is False
    assert api.posts == []


def test_spoofed_autofix_intent_cannot_suppress_canonical_intent() -> None:
    record = _model_unknown_record()
    name, external_id, _ = autoheal._autofix_intent_identity(record)
    spoofed = {
        "id": 78,
        "name": name,
        "external_id": external_id,
        "head_sha": MAIN,
        "status": "completed",
        "conclusion": "neutral",
        "app": {"id": 1, "slug": "attacker"},
    }
    api = _IntentApi(record, existing=[spoofed])

    assert autoheal._ensure_autofix_submission_intent(api, record, _config()) is True
    assert len(api.posts) == 1


def test_main_drift_after_autofix_intent_blocks_provider_submission() -> None:
    record = _model_unknown_record()
    api = _IntentApi(record, move_main_after_post=True)

    with pytest.raises(autoheal.PolicyBlock, match="main advanced after Autofix submission intent"):
        autoheal._ensure_autofix_submission_intent(api, record, _config())

    assert len(api.posts) == 1
