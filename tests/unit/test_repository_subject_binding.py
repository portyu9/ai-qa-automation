from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

import ai_qa_automation.runtime.workspace_lease as workspace_lease_module
import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import (
    descriptor_relative_authority_supported,
    pin_directory_identity,
)
from ai_qa_automation.runtime.workspace_lease import WorkspaceLease
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError
from ai_qa_automation.tools.subprocess_subject import (
    active_workspace_authority,
    bind_active_workspace_authority,
    clear_active_workspace_authority,
    descriptor_bound_cwd,
)


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-test-git-home"
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


def _init_repo(repo: Path, *, relative: str, data: bytes) -> str:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    target = repo / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    _git(repo, "add", "--", relative)
    _git(repo, "commit", "-q", "-m", "initial")
    return _git(repo, "rev-parse", "HEAD")


def _swap_workspace(workspace: Path, replacement: Path, moved: Path) -> None:
    workspace.rename(moved)
    replacement.rename(workspace)


def test_active_workspace_authority_is_owner_bound_and_clearable(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity = pin_directory_identity(workspace, label="test workspace")

    bind_active_workspace_authority(workspace, identity, owner="lease-one")
    try:
        assert active_workspace_authority(workspace) == identity
        assert clear_active_workspace_authority(workspace, identity, owner="lease-two") is False
        assert active_workspace_authority(workspace) == identity
        with pytest.raises(RuntimeError, match="conflicting active lease authority"):
            bind_active_workspace_authority(workspace, identity, owner="lease-two")
    finally:
        assert clear_active_workspace_authority(workspace, identity, owner="lease-one") is True

    assert active_workspace_authority(workspace) is None


def test_workspace_lease_publishes_and_clears_repository_authority(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-subject-lifecycle")

    assert active_workspace_authority(workspace) is None
    lease.acquire()
    try:
        assert lease.workspace_root_identity is not None
        assert active_workspace_authority(workspace) == lease.workspace_root_identity
    finally:
        lease.release()

    assert active_workspace_authority(workspace) is None


def test_workspace_lease_bind_failure_releases_os_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    failed = WorkspaceLease(artifacts, workspace, "run-bind-failure")

    with monkeypatch.context() as scoped:

        def reject_bind(*args: object, **kwargs: object) -> None:
            raise RuntimeError("synthetic authority publication failure")

        scoped.setattr(workspace_lease_module, "bind_active_workspace_authority", reject_bind)
        with pytest.raises(RuntimeError, match="synthetic authority publication failure"):
            failed.acquire()

    assert active_workspace_authority(workspace) is None
    successor = WorkspaceLease(artifacts, workspace, "run-after-bind-failure")
    successor.acquire()
    successor.release()


def test_active_lease_rejects_whole_workspace_directory_replacement(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    workspace.mkdir()
    replacement.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-directory-replacement")
    lease.acquire()
    try:
        _swap_workspace(workspace, replacement, moved)
        with pytest.raises(RepositorySubjectError, match="changed identity since authorization"):
            RepositoryInspector(workspace)
    finally:
        lease.release()


def test_active_lease_rejects_whole_workspace_symlink_replacement(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    workspace.mkdir()
    replacement.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    lease = WorkspaceLease(artifacts, workspace, "run-symlink-replacement")
    lease.acquire()
    try:
        workspace.rename(moved)
        try:
            workspace.symlink_to(replacement, target_is_directory=True)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {type(exc).__name__}")
        with pytest.raises(RepositorySubjectError, match="could not be pinned"):
            RepositoryInspector(workspace)
    finally:
        lease.release()


def test_git_text_command_stays_on_pinned_subject_when_path_swaps_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    original_sha = _init_repo(workspace, relative="tracked.txt", data=b"original\n")
    replacement_sha = _init_repo(replacement, relative="tracked.txt", data=b"replacement\n")
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
    ) -> BoundedSubprocessResult:
        nonlocal swapped
        if not swapped:
            _swap_workspace(workspace, replacement, moved)
            swapped = True
        return real_run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", swap_then_run)

    observed = inspector._git("rev-parse", "HEAD")

    assert swapped is True
    assert observed == original_sha
    assert _git(workspace, "rev-parse", "HEAD") == replacement_sha


def test_snapshot_fails_closed_after_one_pinned_git_command_if_path_was_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    _init_repo(workspace, relative="tracked.txt", data=b"original\n")
    _init_repo(replacement, relative="tracked.txt", data=b"replacement\n")
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
    ) -> BoundedSubprocessResult:
        nonlocal swapped
        if not swapped:
            _swap_workspace(workspace, replacement, moved)
            swapped = True
        return real_run(
            command,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", swap_then_run)

    with pytest.raises(RepositorySubjectError, match="authorized workspace"):
        inspector.snapshot()

    assert swapped is True


def test_exact_byte_git_read_stays_on_pinned_subject_when_path_swaps_before_spawn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    original_bytes = b"\x00\xfforiginal-bytes\n"
    original_sha = _init_repo(workspace, relative="payload.bin", data=original_bytes)
    replacement_sha = _init_repo(
        replacement,
        relative="payload.bin",
        data=b"replacement-bytes\n",
    )
    assert replacement_sha != original_sha
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    real_run = subprocess.run
    swapped = False

    def swap_then_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        nonlocal swapped
        if not swapped:
            _swap_workspace(workspace, replacement, moved)
            swapped = True
        return real_run(*args, **kwargs)

    monkeypatch.setattr(repository_module.subprocess, "run", swap_then_run)

    observed = inspector.read_file_at(original_sha, "payload.bin")

    assert swapped is True
    assert observed == original_bytes
    assert _git(workspace, "rev-parse", "HEAD") == replacement_sha


def test_fingerprint_rejects_root_replacement_instead_of_hashing_replacement_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    replacement = tmp_path / "replacement"
    moved = tmp_path / "authorized-workspace"
    workspace.mkdir()
    replacement.mkdir()
    (workspace / "tracked.txt").write_text("authorized\n", encoding="utf-8")
    (replacement / "tracked.txt").write_text("replacement\n", encoding="utf-8")
    inspector = RepositoryInspector(
        workspace,
        expected_root_identity=pin_directory_identity(workspace, label="test workspace"),
    )
    real_read = repository_module.read_bytes_confined
    swapped = False

    def swap_then_read(
        root: Path,
        relative_path: str | Path,
        *,
        max_bytes: int,
        label: str,
        expected_root_identity: tuple[int, int] | None = None,
    ) -> bytes:
        nonlocal swapped
        if not swapped:
            _swap_workspace(workspace, replacement, moved)
            swapped = True
        return real_read(
            root,
            relative_path,
            max_bytes=max_bytes,
            label=label,
            expected_root_identity=expected_root_identity,
        )

    monkeypatch.setattr(repository_module, "read_bytes_confined", swap_then_read)

    with pytest.raises(RepositorySubjectError, match="changed root identity"):
        inspector._fingerprint(
            "a" * 40,
            " M tracked.txt",
            ("tracked.txt",),
        )

    assert swapped is True


def test_descriptor_bound_cwd_does_not_inherit_authority_descriptor(tmp_path: Path) -> None:
    _require_descriptor_authority()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    expected = pin_directory_identity(workspace, label="test workspace")

    with descriptor_bound_cwd(
        workspace,
        expected_root_identity=expected,
        label="test subprocess subject",
    ) as cwd:
        descriptor_number = int(cwd.name)
        script = (
            "import os, sys; "
            "fd=int(sys.argv[1]); expected=(int(sys.argv[2]), int(sys.argv[3])); "
            "\ntry:\n st=os.fstat(fd)\nexcept OSError:\n sys.exit(0)\n"
            "sys.exit(1 if (st.st_dev, st.st_ino) == expected else 0)"
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(descriptor_number),
                str(expected[0]),
                str(expected[1]),
            ],
            cwd=cwd,
            check=False,
        )

    assert result.returncode == 0
