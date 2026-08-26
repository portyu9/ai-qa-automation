from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
)
from ai_qa_automation.tools.repository import RepositoryInspector


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-worktree-authority-git-home"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    result = subprocess.run(
        [executable, *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.rstrip("\r\n")


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")


def test_skip_worktree_cannot_hide_raw_worktree_mutation(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "update-index", "--skip-worktree", "tracked.txt")
    (workspace / "tracked.txt").write_text("hidden-change\n", encoding="utf-8")

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.changed_files == ("tracked.txt",)
    assert snapshot.status == " M tracked.txt"
    assert snapshot.fingerprint_complete is True


def test_staged_delete_with_ignored_replacement_binds_physical_replacement(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("tracked.txt\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore")
    _git(workspace, "rm", "--cached", "--", "tracked.txt")
    (workspace / "tracked.txt").write_text("physical-replacement\n", encoding="utf-8")
    assert "tracked.txt" not in _git(workspace, "ls-files", "--others", "--exclude-standard")

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.changed_files == ("tracked.txt",)
    assert snapshot.status == "DM tracked.txt"
    assert snapshot.fingerprint_complete is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are required")
def test_snapshot_detects_mode_change_even_when_core_filemode_is_false(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "config", "core.filemode", "false")
    tracked = workspace / "tracked.txt"
    tracked.chmod(tracked.stat().st_mode | 0o111)
    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("tracked.txt",)
    assert snapshot.status == " M tracked.txt"


def test_status_preserves_and_safely_quotes_adversarial_git_paths(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    strange = " leading\\name\nwith-control "
    (workspace / strange).write_text("payload\n", encoding="utf-8")

    inspector = RepositoryInspector(workspace)
    snapshot = inspector.snapshot()
    raw_diff = inspector.diff(strange)

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == (strange,)
    assert raw_diff == snapshot.status
    assert raw_diff.startswith('?? "')
    assert "\\n" in raw_diff
    assert "\\\\" in raw_diff


def test_snapshot_respects_gitignore_without_executing_content_filters(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore rule")
    (workspace / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    snapshot = RepositoryInspector(workspace).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert snapshot.status == ""


def test_gitlink_worktree_state_is_explicitly_incomplete(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    head = _git(workspace, "rev-parse", "HEAD")
    _git(workspace, "update-index", "--add", "--cacheinfo", f"160000,{head},nested")
    _git(workspace, "commit", "-q", "-m", "add gitlink")

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.fingerprint_complete is False
    assert snapshot.changed_files == ("nested",)
    assert "tracked-nonregular-worktree-unverified" in snapshot.fingerprint_incomplete_reasons


def test_snapshot_fails_closed_when_tracked_file_changes_after_status_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    inspector = RepositoryInspector(workspace)
    real_status = inspector._worktree_status
    calls = 0

    def mutate_after_first_status(
        head_sha: str | None, object_format: str
    ) -> tuple[str, tuple[str, ...], str, tuple[str, ...]]:
        nonlocal calls
        observed = real_status(head_sha, object_format)
        calls += 1
        if calls == 1:
            tracked.write_text("late-mutation\n", encoding="utf-8")
        return observed

    monkeypatch.setattr(inspector, "_worktree_status", mutate_after_first_status)

    snapshot = inspector.snapshot()

    assert calls == 2
    assert snapshot.git_sha is None
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == (
        "repository-state-changed-during-inspection",
    )


def test_snapshot_fails_closed_when_symbolic_head_changes_without_commit_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "branch", "same-commit")
    original_branch = _git(workspace, "symbolic-ref", "--short", "HEAD")
    assert original_branch != "same-commit"
    inspector = RepositoryInspector(workspace)
    real_status = inspector._worktree_status
    calls = 0

    def switch_branch_after_first_status(
        head_sha: str | None, object_format: str
    ) -> tuple[str, tuple[str, ...], str, tuple[str, ...]]:
        nonlocal calls
        observed = real_status(head_sha, object_format)
        calls += 1
        if calls == 1:
            (workspace / ".git" / "HEAD").write_text(
                "ref: refs/heads/same-commit\n", encoding="ascii"
            )
        return observed

    monkeypatch.setattr(inspector, "_worktree_status", switch_branch_after_first_status)

    snapshot = inspector.snapshot()

    assert snapshot.git_sha is None
    assert snapshot.branch is None
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == ("git-inspection-incomplete",)
