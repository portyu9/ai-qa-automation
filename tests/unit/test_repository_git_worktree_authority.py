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


def test_repository_inspection_ignores_hostile_core_worktree_redirect(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external_worktree = tmp_path / "external-worktree"
    _init_repo(workspace)
    external_worktree.mkdir()
    (external_worktree / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(workspace, "config", "core.worktree", str(external_worktree))
    (workspace / "tracked.txt").write_text("workspace-mutated\n", encoding="utf-8")

    # Without an explicit worktree binding, repository-local config can hide the
    # actual workspace mutation by redirecting Git to attacker-chosen bytes.
    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""

    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    snapshot = inspector.snapshot()
    diff = inspector.diff("tracked.txt")

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("tracked.txt",)
    assert " M tracked.txt" in snapshot.status
    assert "+workspace-mutated" in diff
    assert "external-worktree" not in diff


def test_repository_snapshot_does_not_refresh_git_index(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    index = workspace / ".git" / "index"

    # Force Git to re-check a cached stat entry with a deterministic timestamp that
    # cannot equal the just-created index entry. A normal `git status` refreshes the
    # index in this condition; read-only inspection must not do so.
    tracked_ns = 1_262_304_000_123_456_789
    os.utime(tracked, ns=(tracked_ns, tracked_ns))
    old_index_ns = 946_684_800_000_000_000
    os.utime(index, ns=(old_index_ns, old_index_ns))
    before = index.stat()
    before_bytes = index.read_bytes()

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    after = index.stat()
    after_bytes = index.read_bytes()
    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert after_bytes == before_bytes
    assert after.st_ino == before.st_ino
    assert after.st_mtime_ns == before.st_mtime_ns
    assert not (workspace / ".git" / "index.lock").exists()
