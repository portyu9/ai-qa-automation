from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "dependency_trusted_merge.py"
SCRIPT_DIR = SCRIPT.parent


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dependency_trusted_merge_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


merge = _load()
BASE = "b" * 40
PROMOTION_HEAD = "c" * 40
ACTION_HEAD = "d" * 40
RUN_ID = 12345
RUN_ATTEMPT = 1
REPOSITORY = "portyu9/ai-qa-automation"


def _trusted_run(**overrides: Any) -> dict[str, Any]:
    run: dict[str, Any] = {
        "id": RUN_ID,
        "workflow_id": merge.TRUSTED_PR_AUTO_WORKFLOW_ID,
        "run_attempt": RUN_ATTEMPT,
        "name": merge.EXPECTED_GATE_WORKFLOW_NAME,
        "path": merge.EXPECTED_GATE_WORKFLOW_PATH,
        "event": "workflow_run",
        "head_branch": "main",
        "head_sha": BASE,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    run.update(overrides)
    return run


def _promotion_pr(number: int = 314) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "draft": False,
        "user": {
            "login": "portyu9-security-remediator[bot]",
            "id": 333833782,
        },
        "head": {
            "ref": "automation/dependency-promotion-179-" + "1" * 12,
            "sha": PROMOTION_HEAD,
            "repo": {"full_name": REPOSITORY},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": REPOSITORY},
        },
    }


def _action_pr(number: int = 317) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "draft": False,
        "user": {"login": merge.BOT_LOGIN, "id": merge.BOT_USER_ID},
        "head": {
            "ref": "dependabot/github_actions/actions/checkout-8",
            "sha": ACTION_HEAD,
            "repo": {"full_name": REPOSITORY},
        },
        "base": {
            "ref": "main",
            "sha": BASE,
            "repo": {"full_name": REPOSITORY},
        },
    }


class Api:
    def __init__(self, pulls: list[dict[str, Any]], *, run: dict[str, Any] | None = None) -> None:
        self.pulls = pulls
        self.run = run or _trusted_run()

    def get(self, path: str) -> dict[str, Any]:
        assert path == f"/actions/runs/{RUN_ID}"
        return self.run

    def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
        assert path == "/pulls?state=open&base=main&sort=created&direction=asc"
        assert max_pages == 4
        return self.pulls


@pytest.fixture
def config() -> dict[str, Any]:
    return {"repository": REPOSITORY, "baseBranch": "main"}


@pytest.mark.parametrize(
    "authority_path",
    (
        ".github/scripts/dependency_trusted_merge.py",
        ".github/scripts/dependency_user_approval.py",
        ".github/workflows/dependency-trusted-merge.yml",
    ),
)
def test_trusted_merge_authority_paths_require_manual_review(
    tmp_path: Path,
    authority_path: str,
) -> None:
    live_config = merge.load_config()
    assert authority_path in live_config["manualReviewPaths"]

    mutated = dict(live_config)
    mutated["manualReviewPaths"] = [
        path for path in live_config["manualReviewPaths"] if path != authority_path
    ]
    config_path = tmp_path / "dependency-governance.json"
    config_path.write_text(json.dumps(mutated), encoding="utf-8")

    with pytest.raises(merge.GovernanceError, match="must require manual review"):
        merge.load_config(config_path)


def test_resolves_exact_promotion_bound_to_same_trusted_run(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    monkeypatch.setattr(
        merge,
        "require_promotion_trusted_gate",
        lambda api, number, head, base: {"runId": RUN_ID, "runAttempt": RUN_ATTEMPT},
    )
    monkeypatch.setattr(
        merge,
        "require_action_trusted_gate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("wrong lane")),
    )

    assert merge.resolve_trusted_dependency_target(
        Api([_promotion_pr()]),
        config,
        trusted_run_id=RUN_ID,
        trusted_run_attempt=RUN_ATTEMPT,
    ) == (merge.LANE_PROMOTION, 314)


def test_resolves_exact_dependabot_actions_bound_to_same_trusted_run(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    monkeypatch.setattr(
        merge,
        "require_action_trusted_gate",
        lambda api, number, head, base: {"runId": RUN_ID, "runAttempt": RUN_ATTEMPT},
    )
    monkeypatch.setattr(
        merge,
        "require_promotion_trusted_gate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("wrong lane")),
    )

    assert merge.resolve_trusted_dependency_target(
        Api([_action_pr()]),
        config,
        trusted_run_id=RUN_ID,
        trusted_run_attempt=RUN_ATTEMPT,
    ) == (merge.LANE_ACTIONS, 317)


def test_unrelated_trusted_run_is_safe_noop(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    monkeypatch.setattr(
        merge,
        "require_promotion_trusted_gate",
        lambda api, number, head, base: {"runId": RUN_ID + 1, "runAttempt": RUN_ATTEMPT},
    )

    assert merge.resolve_trusted_dependency_target(
        Api([_promotion_pr()]),
        config,
        trusted_run_id=RUN_ID,
        trusted_run_attempt=RUN_ATTEMPT,
    ) == (merge.LANE_NONE, None)


def test_one_trusted_run_cannot_authorize_multiple_dependency_subjects(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    evidence = {"runId": RUN_ID, "runAttempt": RUN_ATTEMPT}
    monkeypatch.setattr(merge, "require_promotion_trusted_gate", lambda *args, **kwargs: evidence)
    monkeypatch.setattr(merge, "require_action_trusted_gate", lambda *args, **kwargs: evidence)

    with pytest.raises(merge.GovernanceError, match="multiple dependency merge subjects"):
        merge.resolve_trusted_dependency_target(
            Api([_promotion_pr(), _action_pr()]),
            config,
            trusted_run_id=RUN_ID,
            trusted_run_attempt=RUN_ATTEMPT,
        )


@pytest.mark.parametrize(
    ("override", "message"),
    (
        ({"workflow_id": 999}, "not exact dependency authority"),
        ({"run_attempt": 2}, "not exact dependency authority"),
        ({"event": "issue_comment"}, "not exact dependency authority"),
        ({"head_sha": "e" * 40}, "not exact dependency authority"),
        ({"conclusion": "failure"}, "not exact dependency authority"),
    ),
)
def test_rejects_noncanonical_upstream_trusted_run_before_candidate_scan(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
    override: dict[str, Any],
    message: str,
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    with pytest.raises(merge.GovernanceError, match=message):
        merge.resolve_trusted_dependency_target(
            Api([], run=_trusted_run(**override)),
            config,
            trusted_run_id=RUN_ID,
            trusted_run_attempt=RUN_ATTEMPT,
        )


def test_stale_candidate_base_cannot_match(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(merge, "require_current_control_revision", lambda api, cfg: BASE)
    candidate = _promotion_pr()
    candidate["base"]["sha"] = "f" * 40
    monkeypatch.setattr(
        merge,
        "require_promotion_trusted_gate",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("stale lane reached gate")),
    )

    assert merge.resolve_trusted_dependency_target(
        Api([candidate]),
        config,
        trusted_run_id=RUN_ID,
        trusted_run_attempt=RUN_ATTEMPT,
    ) == (merge.LANE_NONE, None)


def test_target_output_is_closed_and_uses_inherited_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert (
        merge._target_output(lane=merge.LANE_PROMOTION, pr_number=314)
        == "lane=dependency-promotion\npr_number=314\n"
    )
    assert merge._target_output(lane=merge.LANE_NONE, pr_number=None) == "lane=none\npr_number=\n"
    with pytest.raises(merge.GovernanceError, match="outside reviewed policy"):
        merge._target_output(lane="other", pr_number=314)
    with pytest.raises(merge.GovernanceError, match="unexpectedly carries a PR"):
        merge._target_output(lane=merge.LANE_NONE, pr_number=314)

    output = tmp_path / "runner-output"
    with output.open("ab", buffering=0) as handle:
        monkeypatch.setattr(merge, "TARGET_OUTPUT_FD", handle.fileno())
        merge._publish_target(lane=merge.LANE_PROMOTION, pr_number=314)
    assert output.read_text(encoding="utf-8") == "lane=dependency-promotion\npr_number=314\n"
