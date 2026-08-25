from __future__ import annotations

import os
from pathlib import Path

import pytest

from ai_qa_automation.runtime.bootstrap import _contract_drift_reports
from ai_qa_automation.tools.repository import RepositoryChangeSet


class Inspector:
    def __init__(self, baseline: bytes | None) -> None:
        self.baseline = baseline

    def read_file_at(self, ref: str, relative: str, *, max_bytes: int) -> bytes:
        del ref, relative, max_bytes
        if self.baseline is None:
            raise FileNotFoundError
        return self.baseline


def test_current_contract_symlink_is_not_followed(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    outside = tmp_path.parent / f"{tmp_path.name}-contract-outside"
    outside.write_text('{"openapi":"3.1.0"}', encoding="utf-8")
    (tmp_path / "openapi.json").symlink_to(outside)

    reports = _contract_drift_reports(
        workspace=tmp_path,
        inspector=Inspector(b'{"openapi":"3.0.0"}'),  # type: ignore[arg-type]
        change_set=RepositoryChangeSet(
            requested_base_ref="main",
            baseline_sha="base",
            merge_base_sha="base",
            head_sha="head",
            committed_files=("openapi.json",),
            worktree_files=(),
            changed_files=("openapi.json",),
        ),
        changed_files=("openapi.json",),
    )

    assert reports == [
        {
            "path": "openapi.json",
            "contract_kind": "openapi",
            "severity": "NOT_ANALYZED",
            "changes": [],
            "analyzed": False,
            "reason": "current read failed: ValueError",
        }
    ]


def test_added_current_contract_requires_successful_confined_read(tmp_path: Path) -> None:
    (tmp_path / "openapi.json").write_text('{"openapi":"3.1.0"}', encoding="utf-8")

    reports = _contract_drift_reports(
        workspace=tmp_path,
        inspector=Inspector(None),  # type: ignore[arg-type]
        change_set=RepositoryChangeSet(
            requested_base_ref="main",
            baseline_sha="base",
            merge_base_sha="base",
            head_sha="head",
            committed_files=("openapi.json",),
            worktree_files=(),
            changed_files=("openapi.json",),
        ),
        changed_files=("openapi.json",),
    )

    assert reports[0]["severity"] == "NON_BREAKING"
    assert reports[0]["changes"][0]["rule_id"] == "OAS-CONTRACT-ADDED"  # type: ignore[index]


def test_removed_current_contract_is_reported_from_confined_missing_state(tmp_path: Path) -> None:
    reports = _contract_drift_reports(
        workspace=tmp_path,
        inspector=Inspector(b'{"openapi":"3.0.0"}'),  # type: ignore[arg-type]
        change_set=RepositoryChangeSet(
            requested_base_ref="main",
            baseline_sha="base",
            merge_base_sha="base",
            head_sha="head",
            committed_files=("openapi.json",),
            worktree_files=(),
            changed_files=("openapi.json",),
        ),
        changed_files=("openapi.json",),
    )

    assert reports[0]["severity"] == "BREAKING"
    assert reports[0]["changes"][0]["rule_id"] == "OAS-CONTRACT-REMOVED"  # type: ignore[index]
