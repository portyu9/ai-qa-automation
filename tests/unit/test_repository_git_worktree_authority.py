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
    assert snapshot.status == " M tracked.txt"
    assert "tracked.txt" in diff
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


def test_repository_inspection_never_executes_configured_clean_filter(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    filter_log = tmp_path / "filter.log"
    filter_script = tmp_path / "filter.sh"
    filter_script.write_text(
        f"#!/bin/sh\nprintf 'ran\\n' >> {filter_log!s}\ncat\n",
        encoding="utf-8",
    )
    filter_script.chmod(0o755)
    _git(workspace, "config", "filter.hostile.clean", str(filter_script))
    (workspace / ".gitattributes").write_text("*.txt filter=hostile\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitattributes")
    _git(workspace, "commit", "-q", "-m", "attributes")

    filter_log.unlink(missing_ok=True)
    tracked = workspace / "tracked.txt"
    first_ns = 1_262_304_000_123_456_790
    os.utime(tracked, ns=(first_ns, first_ns))
    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""
    assert filter_log.read_text(encoding="utf-8") == "ran\n"

    filter_log.unlink()
    second_ns = first_ns + 1
    os.utime(tracked, ns=(second_ns, second_ns))
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    snapshot = inspector.snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert not filter_log.exists()

    tracked.write_text("workspace-mutated\n", encoding="utf-8")
    raw_diff = inspector.diff("tracked.txt")
    assert "tracked.txt" in raw_diff
    assert not filter_log.exists()


def test_repository_fingerprint_binds_staged_index_content(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )

    tracked.write_text("stage-one\n", encoding="utf-8")
    _git(workspace, "add", "--", "tracked.txt")
    tracked.write_text("same-worktree\n", encoding="utf-8")
    first = inspector.snapshot()

    tracked.write_text("stage-two\n", encoding="utf-8")
    _git(workspace, "add", "--", "tracked.txt")
    tracked.write_text("same-worktree\n", encoding="utf-8")
    second = inspector.snapshot()

    assert first.git_sha == second.git_sha
    assert first.status == second.status
    assert first.changed_files == second.changed_files == ("tracked.txt",)
    assert first.fingerprint != second.fingerprint


def test_clean_large_tracked_file_fails_closed_when_raw_verification_exceeds_bound(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.name", "AI QA Test")
    _git(workspace, "config", "user.email", "aiqa@example.invalid")
    large = workspace / "large.bin"
    large.write_bytes(b"x" * 16_000_001)
    _git(workspace, "add", "--", "large.bin")
    _git(workspace, "commit", "-q", "-m", "large")

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.changed_files == ("large.bin",)
    assert snapshot.status == " M large.bin"
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == (
        "changed-file-byte-limit-exceeded",
        "worktree-file-byte-limit-exceeded",
    )


def test_assume_unchanged_cannot_hide_raw_worktree_mutation(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "update-index", "--assume-unchanged", "tracked.txt")
    (workspace / "tracked.txt").write_text("hidden-change\n", encoding="utf-8")
    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""

    snapshot = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    ).snapshot()

    assert snapshot.changed_files == ("tracked.txt",)
    assert snapshot.status == " M tracked.txt"
    assert snapshot.fingerprint_complete is True
