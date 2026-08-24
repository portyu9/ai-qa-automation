from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.fs_authority as fs_authority
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import RuntimeControl


def _control(tmp_path: Path, workspace: Path) -> RuntimeControl:
    run_dir = tmp_path / "artifacts" / "run-filesystem-authority"
    run_dir.mkdir(parents=True)
    return RuntimeControl(
        workspace=workspace,
        budget=ExecutionBudget(
            max_tool_calls=10,
            max_network_calls=5,
            max_mutations=5,
            max_wall_seconds=60,
        ),
        journal=RunJournal(run_dir / "journal.jsonl"),
        metadata_path=run_dir / "runtime.json",
        lease_id="lease-filesystem-authority",
    )


def test_runtime_rollback_cannot_be_redirected_by_parent_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("original\n", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_target = outside / target.name
    outside_target.write_text("outside-owned\n", encoding="utf-8")

    control = _control(tmp_path, workspace)
    control.prepare_mutation("tests/test_checkout.py")
    target.write_text("candidate\n", encoding="utf-8")

    real_rename = os.rename
    swapped = False

    def swap_parent_before_publish(
        src: str | bytes,
        dst: str | bytes,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal swapped
        if not swapped and src_dir_fd is not None and dst_dir_fd is not None:
            swapped = True
            owned_parent = workspace / "tests-owned"
            real_rename(workspace / "tests", owned_parent)
            try:
                (workspace / "tests").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")
        real_rename(
            src,
            dst,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(fs_authority.os, "rename", swap_parent_before_publish)

    rolled_back = control.rollback_pending_mutation(reason="adversarial parent swap")

    assert swapped is True
    assert rolled_back == "tests/test_checkout.py"
    assert outside_target.read_text(encoding="utf-8") == "outside-owned\n"
    assert (workspace / "tests-owned" / target.name).read_text(encoding="utf-8") == "original\n"
    assert (workspace / "tests").is_symlink()
