from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-untracked-namespace-git-home"
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
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")


def test_nested_entry_aba_changes_worktree_namespace_observation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "nested"
    nested.mkdir()
    subject = nested / "subject.txt"
    subject.write_text("untracked\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)

    before = inspector._worktree_namespace_observation()
    temporary = tmp_path / "subject-temporary.txt"
    subject.replace(temporary)
    temporary.replace(subject)
    after = inspector._worktree_namespace_observation()

    assert before != after
    assert subject.read_text(encoding="utf-8") == "untracked\n"


def test_gitignore_in_place_aba_changes_worktree_namespace_observation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    ignore = repo / ".gitignore"
    ignore.write_text("alpha\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)

    before = inspector._worktree_namespace_observation()
    ignore.write_text("bravo\n", encoding="utf-8")
    ignore.write_text("alpha\n", encoding="utf-8")
    after = inspector._worktree_namespace_observation()

    assert before != after
    assert ignore.read_text(encoding="utf-8") == "alpha\n"


def test_nested_git_directory_metadata_is_bound_by_worktree_observation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "nested"
    nested.mkdir()
    _git(nested, "init", "-q")
    head = nested / ".git" / "HEAD"
    original = head.read_bytes()
    inspector = RepositoryInspector(repo)

    before = inspector._worktree_namespace_observation()
    assert any(path == "file:nested/.git/HEAD" for path, _signature in before)
    head.write_bytes(b"ref: refs/heads/transient\n")
    head.write_bytes(original)
    after = inspector._worktree_namespace_observation()

    assert before != after
    assert head.read_bytes() == original


def test_nested_gitfile_authority_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "nested"
    nested.mkdir()
    external = tmp_path / "external-git-dir"
    external.mkdir()
    (nested / ".git").write_text(f"gitdir: {external}\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)

    with pytest.raises(RepositorySubjectError, match="gitfile"):
        inspector._worktree_namespace_observation()


def test_nested_git_symlink_authority_is_rejected(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink setup differs on Windows")
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "nested"
    nested.mkdir()
    external = tmp_path / "external-git-dir"
    external.mkdir()
    (nested / ".git").symlink_to(external, target_is_directory=True)
    inspector = RepositoryInspector(repo)

    with pytest.raises(RepositorySubjectError, match="filesystem aliases"):
        inspector._worktree_namespace_observation()


def test_nested_git_common_directory_indirection_is_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    nested = repo / "nested"
    nested.mkdir()
    _git(nested, "init", "-q")
    (nested / ".git" / "commondir").write_text("../../external-common\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)

    with pytest.raises(RepositorySubjectError, match="external indirection"):
        inspector._worktree_namespace_observation()


def test_git_metadata_in_place_aba_changes_git_metadata_observation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    exclude = repo / ".git" / "info" / "exclude"
    exclude.write_text("alpha\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)

    before = inspector._git_metadata_observation()
    exclude.write_text("bravo\n", encoding="utf-8")
    exclude.write_text("alpha\n", encoding="utf-8")
    after = inspector._git_metadata_observation()

    assert before != after
    assert exclude.read_text(encoding="utf-8") == "alpha\n"


def test_git_text_command_rejects_changed_metadata_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    inspector = RepositoryInspector(repo)
    observations = iter(
        (
            (("file:config", (1, 2, 3, 4, 5, 6)),),
            (("file:config", (1, 2, 3, 4, 5, 7)),),
        )
    )
    monkeypatch.setattr(inspector, "_git_metadata_observation", lambda: next(observations))

    with pytest.raises(RuntimeError, match="Git metadata changed"):
        inspector._git("rev-parse", "--show-object-format")


def test_git_wrapper_preserves_inner_failure_when_metadata_also_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    inspector = RepositoryInspector(repo)
    observations = iter(
        (
            (("file:config", (1, 2, 3, 4, 5, 6)),),
            (("file:config", (1, 2, 3, 4, 5, 7)),),
        )
    )
    monkeypatch.setattr(inspector, "_git_metadata_observation", lambda: next(observations))

    with pytest.raises(ValueError, match="unsupported Git inspection command"):
        inspector._git("status")


def test_untracked_enumeration_rejects_changed_namespace_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _init_repo(repo)
    (repo / "untracked.txt").write_text("payload\n", encoding="utf-8")
    inspector = RepositoryInspector(repo)
    observations = iter(
        (
            (("dir:.", (1, 2, 3, 4, 5, 6)),),
            (("dir:.", (1, 2, 3, 4, 5, 7)),),
        )
    )
    monkeypatch.setattr(inspector, "_worktree_namespace_observation", lambda: next(observations))

    with pytest.raises(RuntimeError, match="worktree namespace changed"):
        inspector._git_path_list("ls-files", "--others", "--exclude-standard", "-z", "--")
