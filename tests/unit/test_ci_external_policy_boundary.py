from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

import scripts.verify_ci_contract as ci_contract

ROOT = Path(__file__).resolve().parents[2]
TRUSTED_STATUS_PATH = ROOT / ".github" / "scripts" / "trusted_status.py"
_SPEC = importlib.util.spec_from_file_location("aiqa_test_trusted_status", TRUSTED_STATUS_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load trusted status verifier")
trusted_status = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = trusted_status
_SPEC.loader.exec_module(trusted_status)


def test_ci_contract_reports_autonomous_governed_bot_boundary() -> None:
    result = ci_contract.verify_ci_contract(ROOT)
    ordinary = result["workflows"]["automatic"]
    trusted_auto = result["workflows"]["trusted_auto"]
    limitations = "\n".join(result["limitations"])

    assert ordinary["status_write_authority"] == "isolated-generated-maintenance-check-publication"
    assert ordinary["protected_maintenance_authority"] == "centralized-app-gate-for-governed-bots"
    assert trusted_auto["status_writer"] == "dedicated-github-app"
    assert trusted_auto["maintenance_authority"] == (
        "autonomous-governed-bots;external-one-shot-only-for-unrecognized-protected-change"
    )
    assert "automatic read-only development evidence" in limitations
    assert "finite governed bot lanes" in limitations
    assert "autonomously admitted by the centralized App gate" in limitations
    assert "unrecognized protected maintenance" in limitations
    assert "App status-write credentials itself" in limitations
    assert "exact PR/base/head/merge-bound" in limitations
    assert "defense in depth" in limitations


class _TrustedStatusApi:
    def __init__(self, *, target_merge: str | None = None, run_path: str | None = None) -> None:
        self.pr_number = 7
        self.head_sha = "b" * 40
        self.base_sha = "a" * 40
        self.merge_sha = "c" * 40
        self.run_id = 42
        self.target_merge = target_merge or self.merge_sha
        self.run_path = run_path or ".github/workflows/trusted-pr-auto.yml"

    def list_all(self, path: str, *, max_pages: int = 4) -> list[dict[str, Any]]:
        assert path == f"/commits/{self.head_sha}/statuses"
        assert max_pages == 4
        return [
            {
                "id": 99,
                "context": "Trusted PR Gate",
                "state": "success",
                "description": "Automatic exact-subject trusted validation passed",
                "target_url": (
                    "https://github.com/portyu9/ai-qa-automation/actions/runs/"
                    f"{self.run_id}?pr={self.pr_number}&base={self.base_sha}"
                    f"&head={self.head_sha}&merge={self.target_merge}"
                ),
                "creator": {
                    "login": "trusted-pr-gate[bot]",
                    "id": 322661847,
                    "type": "Bot",
                },
            }
        ]

    def get(self, path: str) -> dict[str, Any]:
        if path == f"/pulls/{self.pr_number}":
            return {
                "number": self.pr_number,
                "state": "open",
                "draft": False,
                "head": {
                    "sha": self.head_sha,
                    "repo": {"full_name": "portyu9/ai-qa-automation"},
                },
                "base": {
                    "sha": self.base_sha,
                    "ref": "main",
                    "repo": {"full_name": "portyu9/ai-qa-automation"},
                },
            }
        if path == f"/git/ref/pull/{self.pr_number}/merge":
            return {
                "ref": f"refs/pull/{self.pr_number}/merge",
                "object": {"type": "commit", "sha": self.merge_sha},
            }
        if path == f"/git/commits/{self.merge_sha}":
            return {
                "sha": self.merge_sha,
                "parents": [{"sha": self.base_sha}, {"sha": self.head_sha}],
            }
        if path == f"/actions/runs/{self.run_id}":
            return {
                "id": self.run_id,
                "name": "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework",
                "path": self.run_path,
                "event": "workflow_run",
                "head_branch": "main",
                "head_sha": self.base_sha,
                "status": "completed",
                "conclusion": "success",
                "repository": {"full_name": "portyu9/ai-qa-automation"},
                "head_repository": {"full_name": "portyu9/ai-qa-automation"},
            }
        raise AssertionError(f"unexpected API path: {path}")


def test_trusted_status_accepts_exact_live_subject_and_gate_run() -> None:
    api = _TrustedStatusApi()

    status = trusted_status.require_automatic_trusted_gate(
        api,
        api.pr_number,
        api.head_sha,
        api.base_sha,
    )

    assert status["state"] == "success"


def test_trusted_status_rejects_stale_base_binding() -> None:
    api = _TrustedStatusApi()

    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="bound to a stale subject",
    ):
        trusted_status.require_automatic_trusted_gate(
            api,
            api.pr_number,
            api.head_sha,
            "d" * 40,
        )


def test_trusted_status_rejects_stale_merge_binding() -> None:
    api = _TrustedStatusApi(target_merge="d" * 40)

    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="merge ref drifted",
    ):
        trusted_status.require_automatic_trusted_gate(
            api,
            api.pr_number,
            api.head_sha,
            api.base_sha,
        )


def test_trusted_status_rejects_wrong_gate_workflow_identity() -> None:
    api = _TrustedStatusApi(run_path=".github/workflows/ci.yml")

    with pytest.raises(
        trusted_status.TrustedStatusError,
        match="target run is not exact-current-main gate evidence",
    ):
        trusted_status.require_automatic_trusted_gate(
            api,
            api.pr_number,
            api.head_sha,
            api.base_sha,
        )
