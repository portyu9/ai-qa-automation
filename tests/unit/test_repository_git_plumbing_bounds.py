from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
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


def test_non_git_workspace_remains_explicitly_non_git_without_launching_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "plain.txt").write_text("plain\n", encoding="utf-8")
    inspector = RepositoryInspector(workspace)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"Git must not launch for non-Git workspace: {args}, {kwargs}")

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", forbidden)
    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", forbidden)

    snapshot = inspector.snapshot()

    assert snapshot.git_sha is None
    assert snapshot.branch is None
    assert snapshot.status == ""
    assert snapshot.changed_files == ()
    assert snapshot.fingerprint_complete is True


def test_git_path_list_fails_closed_on_path_count_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    inspector = RepositoryInspector(workspace)
    payload = b"".join(f"p{i}\0".encode() for i in range(100_001))
    monkeypatch.setattr(inspector, "_git_bytes", lambda *args, **kwargs: payload)

    with pytest.raises(RuntimeError, match="path budget"):
        inspector._git_path_list("ls-files", "--others", "--exclude-standard", "-z", "--")


def test_metadata_git_boundary_rejects_content_rendering_commands(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    inspector = RepositoryInspector(workspace)

    with pytest.raises(ValueError, match="unsupported Git inspection command"):
        inspector._git("status", "--porcelain=v1")
    with pytest.raises(ValueError, match="unsupported Git inspection command"):
        inspector._git("diff", "--name-only")


def test_change_set_uses_tree_metadata_without_executing_content_filters(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    baseline = _git(workspace, "rev-parse", "HEAD")
    _git(workspace, "branch", "baseline", baseline)
    marker = tmp_path / "filter-ran"
    filter_script = tmp_path / "filter.py"
    filter_script.write_text(
        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ran'); "
        "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
        encoding="utf-8",
    )
    (workspace / ".gitattributes").write_text("*.txt filter=evil\n", encoding="utf-8")
    _git(workspace, "config", "filter.evil.clean", f"{sys.executable} {filter_script} {marker}")
    _git(workspace, "config", "filter.evil.required", "true")
    (workspace / "committed.py").write_text("value = 1\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitattributes", "committed.py")
    _git(workspace, "commit", "-q", "-m", "head")
    marker.unlink(missing_ok=True)
    (workspace / "untracked.py").write_text("value = 2\n", encoding="utf-8")

    change_set = RepositoryInspector(workspace).change_set("baseline")

    assert marker.exists() is False
    assert change_set.baseline_sha == baseline
    assert set(change_set.committed_files) == {".gitattributes", "committed.py"}
    assert "untracked.py" in change_set.worktree_files
    assert set(change_set.changed_files) == {".gitattributes", "committed.py", "untracked.py"}
