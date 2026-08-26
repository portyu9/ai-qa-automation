from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
)
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


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


def test_repository_inspection_rejects_symlink_git_directory(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external_git_dir = tmp_path / "external-git-dir"
    _init_repo(workspace)
    (workspace / ".git").rename(external_git_dir)
    try:
        (workspace / ".git").symlink_to(external_git_dir, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RepositorySubjectError, match="Git metadata"):
        RepositoryInspector(workspace).snapshot()


def test_repository_inspection_rejects_external_gitfile_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external_git_dir = tmp_path / "external-git-dir"
    _init_repo(workspace)
    (workspace / ".git").rename(external_git_dir)
    (workspace / ".git").write_text(f"gitdir: {external_git_dir}\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="Git metadata"):
        RepositoryInspector(workspace).snapshot()


def test_git_metadata_stays_on_pinned_directory_when_dotgit_swaps_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved_git_dir = workspace / ".git-authorized"
    _init_repo(workspace)
    original_sha = _git(workspace, "rev-parse", "HEAD")
    _init_repo(replacement)
    (replacement / "tracked.txt").write_text("replacement\n", encoding="utf-8")
    _git(replacement, "add", "--", "tracked.txt")
    _git(replacement, "commit", "-q", "-m", "replacement")
    replacement_sha = _git(replacement, "rev-parse", "HEAD")
    assert replacement_sha != original_sha

    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    real_run = repository_module.run_bounded_subprocess
    swapped = False

    def swap_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedSubprocessResult:
        nonlocal swapped
        if not swapped:
            (workspace / ".git").rename(moved_git_dir)
            (replacement / ".git").rename(workspace / ".git")
            swapped = True
        return real_run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            pass_fds=pass_fds,
        )

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", swap_then_run)

    with pytest.raises(RepositorySubjectError, match="metadata changed identity"):
        inspector._git("rev-parse", "HEAD")

    assert swapped is True
    assert _git(workspace, "rev-parse", "HEAD") == replacement_sha


def test_repository_rejects_external_git_config_include(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    external = tmp_path / "external.config"
    external.write_text("[core]\n\tfilemode = false\n", encoding="utf-8")
    with (workspace / ".git" / "config").open("a", encoding="utf-8") as stream:
        stream.write(f"\n[include]\n\tpath = {external}\n")

    with pytest.raises(RepositorySubjectError, match="external configuration"):
        RepositoryInspector(workspace)


def test_repository_rejects_external_git_worktree_config_include(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "config", "extensions.worktreeConfig", "true")
    external = tmp_path / "external-worktree.config"
    external.write_text("[core]\n\tfilemode = false\n", encoding="utf-8")
    (workspace / ".git" / "config.worktree").write_text(
        f"[include]\n\tpath = {external}\n",
        encoding="utf-8",
    )
    assert _git(workspace, "config", "core.filemode") == "false"

    with pytest.raises(RepositorySubjectError, match="external configuration"):
        RepositoryInspector(workspace)


def test_repository_rejects_legacy_git_grafts_without_warning_dependency(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    head = _git(workspace, "rev-parse", "HEAD")
    (workspace / ".git" / "info" / "grafts").write_text(f"{head}\n", encoding="ascii")

    with pytest.raises(RepositorySubjectError, match="legacy graft metadata"):
        RepositoryInspector(workspace)


def test_repository_rejects_nested_git_metadata_symlink(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    heads = workspace / ".git" / "refs" / "heads"
    moved = tmp_path / "heads"
    heads.rename(moved)
    try:
        heads.symlink_to(moved, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RepositorySubjectError, match="unsafe or unreadable"):
        RepositoryInspector(workspace)


def test_worktree_metadata_command_fails_closed_if_dotgit_swaps_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved_git_dir = workspace / ".git-authorized"
    _init_repo(workspace)
    _init_repo(replacement)
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    real_run = repository_module.run_bounded_binary_subprocess
    swapped = False

    def swap_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_stdout_bytes: int = 2_000_000,
        max_stderr_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ):
        nonlocal swapped
        if not swapped:
            (workspace / ".git").rename(moved_git_dir)
            (replacement / ".git").rename(workspace / ".git")
            swapped = True
        return real_run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            pass_fds=pass_fds,
        )

    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", swap_then_run)

    with pytest.raises(RepositorySubjectError, match="metadata changed identity"):
        inspector.snapshot()
    assert swapped is True


def test_repository_rejects_git_common_directory_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".git" / "commondir").write_text("../external\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="external common/object storage"):
        RepositoryInspector(workspace)


def test_repository_rejects_git_alternate_object_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    info = workspace / ".git" / "objects" / "info"
    info.mkdir(exist_ok=True)
    (info / "alternates").write_text("/tmp/external-objects\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="external common/object storage"):
        RepositoryInspector(workspace)


def test_repository_inspection_fails_closed_without_descriptor_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(repository_module, "descriptor_relative_authority_supported", lambda: False)

    with pytest.raises(RepositorySubjectError, match="requires descriptor-bound"):
        RepositoryInspector(workspace)
