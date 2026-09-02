from __future__ import annotations

import os
from pathlib import Path

import pytest

import ai_qa_automation.fs_authority as fs_authority
from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pending_root_authority,
)
from ai_qa_automation.policy import PolicyEngine
from ai_qa_automation.runtime.budget import ExecutionBudget
from ai_qa_automation.runtime.journal import RunJournal
from ai_qa_automation.runtime.run_control import MutationPendingError, RuntimeControl
from ai_qa_automation.tools.safe_patch import SafeTestPatcher


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

    with pytest.raises(ValueError, match="symlinked parent component"):
        control.rollback_pending_mutation(reason="adversarial parent swap")

    assert swapped is True
    assert control.pending_mutation is not None
    assert outside_target.read_text(encoding="utf-8") == "outside-owned\n"
    assert (workspace / "tests-owned" / target.name).read_text(encoding="utf-8") == "original\n"
    assert (workspace / "tests").is_symlink()


def test_safe_patcher_replace_cannot_be_redirected_by_parent_directory_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_ui.py"
    target.parent.mkdir(parents=True)
    original = "def test_button():\n    assert locate('#old')\n"
    target.write_text(original, encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_target = outside / target.name
    outside_target.write_text("outside-owned\n", encoding="utf-8")

    patcher = SafeTestPatcher(
        workspace,
        PolicyEngine(workspace, workspace, allow_test_writes=True),
    )
    digest = patcher.sha256_text(original)

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
            real_rename(workspace / "tests", workspace / "tests-owned")
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

    with pytest.raises(ValueError, match="symlinked parent component"):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256=digest,
            old_text="locate('#old')",
            new_text="locate('#new')",
        )

    assert swapped is True
    assert outside_target.read_text(encoding="utf-8") == "outside-owned\n"
    detached = (workspace / "tests-owned" / target.name).read_text(encoding="utf-8")
    assert "locate('#new')" in detached
    assert "locate('#old')" not in detached
    assert (workspace / "tests").is_symlink()


def test_runtime_rejects_workspace_root_replacement_before_mutation(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_checkout.py"
    target.parent.mkdir(parents=True)
    target.write_text("original\n", encoding="utf-8")
    control = _control(tmp_path, workspace)

    owned_workspace = tmp_path / "sut-owned"
    workspace.rename(owned_workspace)
    replacement_target = workspace / "tests" / target.name
    replacement_target.parent.mkdir(parents=True)
    replacement_target.write_text("original\n", encoding="utf-8")

    with pytest.raises(
        MutationPendingError, match="trusted root changed identity since authorization"
    ):
        control.prepare_mutation("tests/test_checkout.py")

    assert control.pending_mutation is None
    assert replacement_target.read_text(encoding="utf-8") == "original\n"
    assert (owned_workspace / "tests" / target.name).read_text(encoding="utf-8") == "original\n"


def test_safe_patcher_rejects_workspace_root_replacement_before_patch(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_ui.py"
    target.parent.mkdir(parents=True)
    original = "def test_button():\n    assert locate('#old')\n"
    target.write_text(original, encoding="utf-8")
    patcher = SafeTestPatcher(
        workspace,
        PolicyEngine(workspace, workspace, allow_test_writes=True),
    )
    digest = patcher.sha256_text(original)

    owned_workspace = tmp_path / "sut-owned"
    workspace.rename(owned_workspace)
    replacement_target = workspace / "tests" / target.name
    replacement_target.parent.mkdir(parents=True)
    replacement_target.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="trusted root changed identity since authorization"):
        patcher.replace_once(
            relative_path="tests/test_ui.py",
            expected_sha256=digest,
            old_text="locate('#old')",
            new_text="locate('#new')",
        )

    assert replacement_target.read_text(encoding="utf-8") == original
    assert (owned_workspace / "tests" / target.name).read_text(encoding="utf-8") == original


def test_patcher_created_after_prepare_inherits_original_workspace_authority(
    tmp_path: Path,
) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative no-follow filesystem authority is unavailable")

    workspace = tmp_path / "sut"
    target = workspace / "tests" / "test_ui.py"
    target.parent.mkdir(parents=True)
    original = "def test_button():\n    assert locate('#old')\n"
    target.write_text(original, encoding="utf-8")
    control = _control(tmp_path, workspace)
    control.prepare_mutation("tests/test_ui.py")
    assert pending_root_authority(workspace) == control.workspace_identity

    owned_workspace = tmp_path / "sut-owned"
    workspace.rename(owned_workspace)
    replacement_target = workspace / "tests" / target.name
    replacement_target.parent.mkdir(parents=True)
    replacement_target.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="changed identity since mutation authorization"):
        SafeTestPatcher(
            workspace,
            PolicyEngine(workspace, workspace, allow_test_writes=True),
        )

    assert replacement_target.read_text(encoding="utf-8") == original
    replacement_target.unlink()
    replacement_target.parent.rmdir()
    workspace.rmdir()
    owned_workspace.rename(workspace)

    assert control.rollback_pending_mutation(reason="test cleanup") == "tests/test_ui.py"
    assert pending_root_authority(workspace) is None
