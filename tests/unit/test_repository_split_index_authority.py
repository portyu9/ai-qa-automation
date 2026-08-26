from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-split-index-authority-git-home"
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
    _require_descriptor_authority()
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")


def test_snapshot_rejects_active_split_index_before_ls_files_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    _git(repo, "update-index", "--split-index")
    assert _git(repo, "rev-parse", "--shared-index-path")

    def forbidden_binary_git(*args: object, **kwargs: object) -> None:
        raise AssertionError(
            f"split index must be rejected before binary Git execution: {args}, {kwargs}"
        )

    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", forbidden_binary_git)

    with pytest.raises(RepositorySubjectError, match="split-index"):
        RepositoryInspector(repo).snapshot()


def test_snapshot_allows_stale_unreferenced_shared_index_file(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    stale = repo / ".git" / f"sharedindex.{'0' * 40}"
    stale.write_bytes(b"stale shared-index bytes are not active authority\n")
    assert _git(repo, "rev-parse", "--shared-index-path") == ""

    snapshot = RepositoryInspector(repo).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert snapshot.status == ""
