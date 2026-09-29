from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
QUALIFICATION_SCRIPT = SCRIPT_DIR / "trusted_qualification.py"

HEAD = "a" * 40
BASE = "b" * 40
RUN_ID = 778899
CHECK_ID = 445566


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


qualification = _load(QUALIFICATION_SCRIPT, "trusted_qualification_test")


class _Api:
    def __init__(
        self,
        *,
        external_id: str | None = None,
        app_id: int = qualification.GITHUB_ACTIONS_APP_ID,
        workflow_id: int | None = None,
        details_url: str | None = None,
    ) -> None:
        spec = qualification.QUALIFICATION_SPECS["Required PR Gate"]
        self.external_id = external_id or (
            f"{spec['external_prefix']}:{HEAD}:{RUN_ID}:1"
        )
        self.app_id = app_id
        self.workflow_id = int(workflow_id or spec["workflow_id"])
        self.details_url = details_url

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        assert path == f"/commits/{HEAD}/check-runs?filter=latest"
        assert max_pages == 4
        return [
            {
                "id": CHECK_ID,
                "name": "Required PR Gate",
                "head_sha": HEAD,
                "external_id": self.external_id,
                "status": "completed",
                "conclusion": "success",
                # GitHub canonicalizes an Actions-authored check to the publishing job URL.
                "details_url": self.details_url
                or (
                    "https://github.com/portyu9/ai-qa-automation/"
                    "actions/runs/778899/job/998877"
                ),
                "app": {
                    "id": self.app_id,
                    "slug": "github-actions",
                    "name": "GitHub Actions",
                },
            }
        ]

    def get(self, path: str) -> dict[str, Any]:
        assert path == f"/actions/runs/{RUN_ID}"
        spec = qualification.QUALIFICATION_SPECS["Required PR Gate"]
        return {
            "id": RUN_ID,
            "run_attempt": 1,
            "workflow_id": self.workflow_id,
            "name": spec["workflow_name"],
            "path": spec["workflow_path"],
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": BASE,
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": qualification.EXPECTED_REPOSITORY},
            "head_repository": {"full_name": qualification.EXPECTED_REPOSITORY},
            "actor": {
                "login": qualification.GITHUB_ACTIONS_LOGIN,
                "id": qualification.GITHUB_ACTIONS_USER_ID,
            },
            "triggering_actor": {
                "login": qualification.GITHUB_ACTIONS_LOGIN,
                "id": qualification.GITHUB_ACTIONS_USER_ID,
            },
        }


def test_qualification_accepts_github_canonical_job_details_url() -> None:
    evidence = qualification.require_success(
        _Api(),
        HEAD,
        BASE,
        required=("Required PR Gate",),
    )

    assert evidence["Required PR Gate"] == {
        "check_id": CHECK_ID,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "conclusion": "success",
        "details_url": (
            f"https://github.com/{qualification.EXPECTED_REPOSITORY}/actions/runs/{RUN_ID}"
        ),
    }


def test_qualification_rejects_noncanonical_details_url() -> None:
    with pytest.raises(
        qualification.TrustedQualificationError,
        match="details URL is not canonical",
    ):
        qualification.require_success(
            _Api(details_url="https://example.invalid/forged"),
            HEAD,
            BASE,
            required=("Required PR Gate",),
        )


def test_qualification_still_rejects_unbound_external_identity() -> None:
    with pytest.raises(
        qualification.TrustedQualificationError,
        match="external_id is malformed",
    ):
        qualification.require_success(
            _Api(external_id=f"aiqa-ci-qualification:{HEAD}:{RUN_ID}:0"),
            HEAD,
            BASE,
            required=("Required PR Gate",),
        )


def test_qualification_still_rejects_non_actions_writer() -> None:
    with pytest.raises(
        qualification.TrustedQualificationError,
        match="writer is not GitHub Actions",
    ):
        qualification.require_success(
            _Api(app_id=qualification.GITHUB_ACTIONS_APP_ID + 1),
            HEAD,
            BASE,
            required=("Required PR Gate",),
        )
