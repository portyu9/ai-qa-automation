"""Adversarial read-only stale route-plan supersession and downstream privilege gates."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import scripts.ci_contract_base as base

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"


def _load_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "security_autoheal_supersession_test", SCRIPT_DIR / "security_autoheal.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load_autoheal()
OLD, NEW = "a" * 40, "b" * 40
RUN_ID, ATTEMPT, ARTIFACT = 12345, 2, 98765
DIGEST = "sha256:" + "d" * 64


def _comparison() -> dict[str, Any]:
    return {
        "status": "ahead",
        "ahead_by": 1,
        "behind_by": 0,
        "base_commit": {"sha": OLD},
        "merge_base_commit": {"sha": OLD},
        "head_commit": {"sha": NEW},
    }


def test_forward_main_rejects_divergence_rewrites_and_second_advance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Api:
        proof: Any = _comparison()
        reads = 0

        def get(self, path: str) -> Any:
            assert path == f"/compare/{OLD}...{NEW}"
            self.reads += 1
            return self.proof

        def post(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("ancestry admission cannot mutate repository")

    api = Api()
    live = [NEW]
    monkeypatch.setattr(autoheal, "_current_main", lambda *_args: live[0])
    config = autoheal.load_config()
    autoheal._require_forward_route_supersession(
        api, config, planned_main_sha=OLD, observed_main_sha=NEW
    )
    assert api.reads == 1
    valid = _comparison()
    for bad in (
        None,
        {},
        {**valid, "status": "diverged"},
        {**valid, "status": "behind"},
        {**valid, "ahead_by": True},
        {**valid, "ahead_by": 0},
        {**valid, "behind_by": True},
        {**valid, "behind_by": 1},
        {**valid, "base_commit": {"sha": NEW}},
        {**valid, "merge_base_commit": {"sha": NEW}},
        {**valid, "head_commit": {"sha": OLD}},
        {**valid, "head_commit": None},
    ):
        api.proof = bad
        with pytest.raises(autoheal.AutohealError, match="forward-only main ancestry"):
            autoheal._require_forward_route_supersession(
                api, config, planned_main_sha=OLD, observed_main_sha=NEW
            )
    api.proof = valid
    live[0] = "c" * 40
    with pytest.raises(autoheal.AutohealError, match="advanced again"):
        autoheal._require_forward_route_supersession(
            api, config, planned_main_sha=OLD, observed_main_sha=NEW
        )
    with pytest.raises(autoheal.AutohealError, match="distinct accepted-main"):
        autoheal._require_forward_route_supersession(
            api, config, planned_main_sha=NEW, observed_main_sha=NEW
        )


def test_stale_plan_requires_artifact_before_nonmutating_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = autoheal.load_config()
    plan = {"mainSha": OLD, "workflowRunId": RUN_ID, "workflowRunAttempt": ATTEMPT}
    observed: list[str] = []

    class Api:
        def get(self, path: str) -> dict[str, Any]:
            assert observed == ["artifact"]
            assert path == f"/compare/{OLD}...{NEW}"
            observed.append("compare")
            return _comparison()

        def post(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("stale plan must not publish a mutation")

        def list_all(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("stale plan must not enumerate alerts or repairs")

    api = Api()
    monkeypatch.setenv("GITHUB_REPOSITORY", config["repository"])
    monkeypatch.setattr(autoheal, "GitHubApi", lambda *_args: api)
    monkeypatch.setattr(autoheal, "_current_main", lambda *_args: NEW)
    monkeypatch.setattr(autoheal, "_load_route_plan", lambda *_args: plan)

    def artifact(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        observed.append("artifact")
        return {"routeArtifactDigest": DIGEST}

    monkeypatch.setattr(autoheal, "_require_route_plan_artifact", artifact)
    kwargs = {
        "route_plan_path": Path("route-plan.json"),
        "route_artifact_id": ARTIFACT,
        "route_artifact_name": f"security-autoheal-route-plan-{RUN_ID}-{ATTEMPT}",
        "route_artifact_digest": DIGEST,
    }
    with pytest.raises(autoheal.SupersededRoutePlan, match="before mutation"):
        autoheal.reconcile(config, allow_merge=True, **kwargs)
    assert observed == ["artifact", "compare"]

    observed.clear()

    def invalid(*_args: Any, **_kwargs: Any) -> None:
        raise autoheal.AutohealError("route plan artifact metadata drifted")

    monkeypatch.setattr(autoheal, "_require_route_plan_artifact", invalid)
    with pytest.raises(autoheal.AutohealError, match="artifact metadata drifted"):
        autoheal.reconcile(config, allow_merge=True, **kwargs)
    assert observed == []


def test_cli_outputs_noop_only_for_authenticated_route_supersession(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = autoheal.load_config()
    output = tmp_path / "GITHUB_OUTPUT"
    output.write_bytes(b"")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(autoheal, "load_config", lambda: config)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "security_autoheal.py", "--reconcile", "--route-plan", "route-plan.json",
            "--route-artifact-id", str(ARTIFACT), "--route-artifact-name", "route-plan-test",
            "--route-artifact-digest", DIGEST, "--reconcile-output", str(output),
        ],
    )

    def stale(*_args: Any, **_kwargs: Any) -> None:
        raise autoheal.SupersededRoutePlan("validated forward-only main advance")

    monkeypatch.setattr(autoheal, "reconcile", stale)
    autoheal.main()
    assert output.read_text(encoding="utf-8") == "active=false\n"
    output.write_bytes(b"")
    monkeypatch.setattr(autoheal, "reconcile", lambda *_args, **_kwargs: 0)
    autoheal.main()
    assert output.read_text(encoding="utf-8") == "active=true\n"

    output.write_bytes(b"")

    def fail(*_args: Any, **_kwargs: Any) -> None:
        raise autoheal.AutohealError("invalid live security evidence")

    monkeypatch.setattr(autoheal, "reconcile", fail)
    with pytest.raises(autoheal.AutohealError, match="invalid live security evidence"):
        autoheal.main()
    assert output.read_bytes() == b""

    alternate = tmp_path / "not-the-github-output"
    alternate.write_bytes(b"")
    with pytest.raises(autoheal.AutohealError, match="exact runner-owned"):
        autoheal._publish_route_reconcile_output(alternate, active=True)


def test_workflow_mandates_active_route_before_approval_and_merge() -> None:
    workflow = (ROOT / ".github" / "workflows" / "security-autoheal.yml").read_text(
        encoding="utf-8"
    )
    reconcile_job = base._job_block(workflow, "reconcile")
    assert "active: " + "$" + "{{ steps.route-reconcile.outputs.active }}" in reconcile_job
    mutation = base._step_block(
        reconcile_job, "Reconcile exact-subject CodeQL remediations from persisted routes"
    )
    assert "id: route-reconcile" in mutation
    assert '--reconcile-output "$GITHUB_OUTPUT"' in mutation
    for downstream in ("approve", "merge"):
        assert "needs.reconcile.outputs.active == 'true'" in base._job_block(
            workflow, downstream
        )
