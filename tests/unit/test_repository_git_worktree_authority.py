from __future__ import annotations

import os
import shutil
import subprocess
import sys
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


def _init_repo(repo: Path, *, data: str = "baseline\n") -> str:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    (repo / "tracked.txt").write_text(data, encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "initial")
    return _git(repo, "rev-parse", "HEAD")


def _inspector(workspace: Path) -> RepositoryInspector:
    return RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )


def test_repository_inspection_ignores_hostile_core_worktree_redirect(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external_worktree = tmp_path / "external-worktree"
    _init_repo(workspace)
    external_worktree.mkdir()
    (external_worktree / "tracked.txt").write_text("baseline\n", encoding="utf-8")
    _git(workspace, "config", "core.worktree", str(external_worktree))
    (workspace / "tracked.txt").write_text("workspace-mutated\n", encoding="utf-8")

    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""

    inspector = _inspector(workspace)
    snapshot = inspector.snapshot()
    raw_diff = inspector.diff("tracked.txt")

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("tracked.txt",)
    assert " M tracked.txt" in snapshot.status
    assert raw_diff == " M tracked.txt"


def test_repository_snapshot_does_not_refresh_git_index(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"
    index = workspace / ".git" / "index"

    tracked_ns = 1_262_304_000_123_456_789
    os.utime(tracked, ns=(tracked_ns, tracked_ns))
    old_index_ns = 946_684_800_000_000_000
    os.utime(index, ns=(old_index_ns, old_index_ns))
    before = index.stat()
    before_bytes = index.read_bytes()

    snapshot = _inspector(workspace).snapshot()

    after = index.stat()
    after_bytes = index.read_bytes()
    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert after_bytes == before_bytes
    assert after.st_ino == before.st_ino
    assert after.st_mtime_ns == before.st_mtime_ns
    assert not (workspace / ".git" / "index.lock").exists()


def test_repository_rejects_symlinked_git_metadata(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external = tmp_path / "external"
    workspace.mkdir()
    _init_repo(external)
    try:
        (workspace / ".git").symlink_to(external / ".git", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RepositorySubjectError, match="direct, no-follow, and self-contained"):
        _inspector(workspace)


def test_repository_rejects_gitfile_metadata_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    external = tmp_path / "external"
    workspace.mkdir()
    _init_repo(external)
    (workspace / ".git").write_text(f"gitdir: {external / '.git'}\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="direct, no-follow, and self-contained"):
        _inspector(workspace)


def test_git_metadata_command_stays_on_pinned_git_dir_when_it_swaps_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    original_sha = _init_repo(workspace, data="original\n")
    replacement_sha = _init_repo(replacement, data="replacement\n")
    assert replacement_sha != original_sha
    inspector = _inspector(workspace)
    real_run = repository_module.run_bounded_subprocess
    moved_git = tmp_path / "original-git"
    swapped = False

    def swap_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
    ) -> BoundedSubprocessResult:
        nonlocal swapped
        if not swapped:
            (workspace / ".git").rename(moved_git)
            (replacement / ".git").rename(workspace / ".git")
            swapped = True
        return real_run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", swap_then_run)

    with pytest.raises(RepositorySubjectError, match="metadata"):
        inspector._git("rev-parse", "HEAD")

    assert swapped is True
    assert _git(workspace, "rev-parse", "HEAD") == replacement_sha
    with pytest.raises(RepositorySubjectError, match="metadata"):
        inspector._git("rev-parse", "HEAD")


def test_snapshot_and_safe_diff_do_not_execute_configured_clean_filter(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
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
    tracked = workspace / "tracked.txt"
    os.utime(tracked, ns=(1_262_304_000_123_456_789, 1_262_304_000_123_456_789))

    _git(workspace, "status", "--porcelain=v1", "--untracked-files=all")
    assert marker.exists(), "negative control did not execute configured clean filter"
    marker.unlink()

    inspector = _inspector(workspace)
    snapshot = inspector.snapshot()
    inspector.diff("tracked.txt")

    assert marker.exists() is False
    assert ".gitattributes" in snapshot.changed_files


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits are required")
def test_snapshot_detects_mode_change_even_when_core_filemode_is_false(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    _git(workspace, "config", "core.filemode", "false")
    tracked = workspace / "tracked.txt"
    tracked.chmod(tracked.stat().st_mode | 0o111)

    assert _git(workspace, "status", "--porcelain=v1", "--untracked-files=all") == ""

    snapshot = _inspector(workspace).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("tracked.txt",)
    assert snapshot.status == " M tracked.txt"


def test_fingerprint_binds_staged_index_bytes_for_same_change_shape(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    tracked = workspace / "tracked.txt"

    tracked.write_text("candidate-one\n", encoding="utf-8")
    _git(workspace, "add", "--", "tracked.txt")
    first = _inspector(workspace).snapshot()

    tracked.write_text("candidate-two\n", encoding="utf-8")
    _git(workspace, "add", "--", "tracked.txt")
    second = _inspector(workspace).snapshot()

    assert first.status == second.status == "M  tracked.txt"
    assert first.changed_files == second.changed_files == ("tracked.txt",)
    assert first.fingerprint_complete is True
    assert second.fingerprint_complete is True
    assert first.fingerprint != second.fingerprint


def test_metadata_git_boundary_rejects_worktree_commands(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    inspector = _inspector(workspace)

    with pytest.raises(ValueError, match="metadata-only"):
        inspector._git("status", "--porcelain=v1")
    with pytest.raises(ValueError, match="metadata-only"):
        inspector._git("diff", "--name-only")


def test_untracked_regular_file_is_observed_without_git_status(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / "new.txt").write_text("new\n", encoding="utf-8")

    snapshot = _inspector(workspace).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ("new.txt",)
    assert snapshot.status == "?? new.txt"


def test_status_preserves_and_safely_quotes_adversarial_git_paths(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    strange = " leading\\name\nwith-control "
    (workspace / strange).write_text("payload\n", encoding="utf-8")

    inspector = _inspector(workspace)
    snapshot = inspector.snapshot()
    raw_diff = inspector.diff(strange)

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == (strange,)
    assert raw_diff == snapshot.status
    assert raw_diff.startswith('?? "')
    assert "\\n" in raw_diff
    assert "\\\\" in raw_diff


def test_repository_rejects_symlinked_git_object_directory(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    original_objects = workspace / ".git" / "objects"
    moved_objects = tmp_path / "objects"
    original_objects.rename(moved_objects)
    try:
        original_objects.symlink_to(moved_objects, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RepositorySubjectError, match="self-contained"):
        _inspector(workspace)


def test_repository_rejects_git_common_directory_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".git" / "commondir").write_text("../external\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="external common/object storage"):
        _inspector(workspace)


def test_repository_rejects_git_alternate_object_indirection(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    info = workspace / ".git" / "objects" / "info"
    info.mkdir(exist_ok=True)
    (info / "alternates").write_text("/tmp/external-objects\n", encoding="utf-8")

    with pytest.raises(RepositorySubjectError, match="external common/object storage"):
        _inspector(workspace)


def test_change_set_uses_tree_metadata_without_executing_content_filters(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    baseline = _init_repo(workspace)
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

    change_set = _inspector(workspace).change_set("baseline")

    assert marker.exists() is False
    assert change_set.baseline_sha == baseline
    assert set(change_set.committed_files) == {".gitattributes", "committed.py"}
    assert "untracked.py" in change_set.worktree_files
    assert set(change_set.changed_files) == {".gitattributes", "committed.py", "untracked.py"}


def test_non_git_workspace_remains_explicitly_non_git_without_launching_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "plain.txt").write_text("plain\n", encoding="utf-8")
    inspector = _inspector(workspace)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError(f"Git must not launch for a non-Git workspace: {args}, {kwargs}")

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", forbidden)
    monkeypatch.setattr(repository_module, "run_bounded_binary_subprocess", forbidden)

    snapshot = inspector.snapshot()

    assert snapshot.git_sha is None
    assert snapshot.branch is None
    assert snapshot.status == ""
    assert snapshot.changed_files == ()
    assert snapshot.fingerprint_complete is True


def test_descriptor_bound_git_metadata_cwd_does_not_inherit_authority_descriptor(
    tmp_path: Path,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    inspector = _inspector(workspace)

    with inspector._git_metadata_cwd() as cwd:
        descriptor_number = int(cwd.name)
        script = (
            "import os,sys; fd=int(sys.argv[1]); "
            "\ntry:\n os.fstat(fd)\nexcept OSError:\n sys.exit(0)\n"
            "sys.exit(1)"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(descriptor_number)],
            cwd=cwd,
            check=False,
        )

    assert result.returncode == 0


def test_repository_rejects_nested_git_metadata_symlink(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    external_config = tmp_path / "external-config"
    external_config.write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    config = workspace / ".git" / "config"
    config.unlink()
    try:
        config.symlink_to(external_config)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")

    with pytest.raises(RepositorySubjectError, match="metadata tree"):
        _inspector(workspace)


def test_snapshot_respects_gitignore_without_executing_content_filters(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    _git(workspace, "add", "--", ".gitignore")
    _git(workspace, "commit", "-q", "-m", "ignore rule")
    (workspace / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    snapshot = _inspector(workspace).snapshot()

    assert snapshot.fingerprint_complete is True
    assert snapshot.changed_files == ()
    assert snapshot.status == ""


def test_untracked_path_limit_is_explicitly_incomplete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    _init_repo(workspace)
    (workspace / "one.txt").write_text("1\n", encoding="utf-8")
    (workspace / "two.txt").write_text("2\n", encoding="utf-8")
    (workspace / "three.txt").write_text("3\n", encoding="utf-8")
    monkeypatch.setattr(repository_module, "_MAX_UNTRACKED_PATHS", 2)

    snapshot = _inspector(workspace).snapshot()

    assert snapshot.fingerprint_complete is False
    assert "worktree-untracked-path-limit-exceeded" in snapshot.fingerprint_incomplete_reasons
    assert len(snapshot.changed_files) == 2
