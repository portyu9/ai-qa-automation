from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools import execution_env
from ai_qa_automation.tools.execution_env import (
    controller_executable_search_path,
    resolve_executable,
    restricted_subprocess_env,
)
from ai_qa_automation.tools.repository import RepositoryInspector


def test_restricted_subprocess_env_replaces_ambient_executable_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile = tmp_path / "target-bin"
    hostile.mkdir()
    monkeypatch.setenv("PATH", f"{hostile}{os.pathsep}.")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "target-venv"))

    env = restricted_subprocess_env(home=tmp_path / "home")

    assert env["PATH"] == controller_executable_search_path()
    assert str(hostile) not in env["PATH"].split(os.pathsep)
    assert "VIRTUAL_ENV" not in env


@pytest.mark.parametrize("key", ["PATH", "Path", "VIRTUAL_ENV", "PATHEXT"])
def test_restricted_subprocess_env_rejects_executable_authority_override(
    tmp_path: Path,
    key: str,
) -> None:
    with pytest.raises(ValueError, match="cannot override executable authority"):
        restricted_subprocess_env(home=tmp_path / "home", extra={key: str(tmp_path)})


def test_resolve_executable_rejects_empty_and_relative_path_roots() -> None:
    executable = str(Path(os.__file__).resolve())

    with pytest.raises(ValueError, match="empty entries"):
        resolve_executable(executable, env={"PATH": f"{Path(executable).parent}{os.pathsep}"})
    with pytest.raises(ValueError, match="absolute trusted roots"):
        resolve_executable(executable, env={"PATH": "."})


def test_resolve_executable_rejects_absolute_runtime_owned_executable(
    tmp_path: Path,
) -> None:
    env = restricted_subprocess_env(home=tmp_path / "home")

    for name in ("target", "artifacts", "evidence"):
        root = tmp_path / name
        root.mkdir()
        candidate = root / "controller-tool"
        candidate.write_text("not trusted controller bytes\n", encoding="utf-8")
        with pytest.raises(PermissionError, match="outside controlled PATH authority roots"):
            resolve_executable(str(candidate), env=env)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics required")
def test_resolve_executable_rejects_symlink_escape_from_authorized_root(tmp_path: Path) -> None:
    trusted_root = tmp_path / "trusted-bin"
    trusted_root.mkdir()
    link = trusted_root / "controller-tool"
    try:
        link.symlink_to(Path(sys.executable).resolve())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(PermissionError, match="outside controlled PATH authority roots"):
        resolve_executable("controller-tool", env={"PATH": str(trusted_root)})


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership/mode invariant")
def test_controller_search_path_rejects_mutable_candidate_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = tmp_path / "mutable-bin"
    candidate.mkdir()
    candidate.chmod(0o777)
    monkeypatch.setattr(execution_env, "_controller_executable_candidates", lambda: (candidate,))

    with pytest.raises(PermissionError, match="controller executable root"):
        controller_executable_search_path()


def test_resolve_executable_binds_named_system_tool_to_controlled_root(tmp_path: Path) -> None:
    env = restricted_subprocess_env(home=tmp_path / "home")

    resolved = Path(resolve_executable("git", env=env))
    roots = tuple(Path(item).resolve() for item in env["PATH"].split(os.pathsep))

    assert resolved.is_absolute()
    assert resolved.is_file()
    assert any(resolved == root or root in resolved.parents for root in roots)


@pytest.mark.skipif(
    os.name == "nt" or not descriptor_relative_authority_supported(),
    reason="adversarial repository executable test requires POSIX descriptor authority",
)
def test_repository_inspector_ignores_target_git_first_on_ambient_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bootstrap_env = restricted_subprocess_env(home=tmp_path / "bootstrap-home")
    trusted_git = resolve_executable("git", env=bootstrap_env)

    def git(*args: str) -> None:
        subprocess.run(
            [trusted_git, *args],
            cwd=workspace,
            env=bootstrap_env,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    git("init", "-q")
    tracked = workspace / "tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")
    git("add", "--", "tracked.txt")
    git(
        "-c",
        "user.name=AI QA",
        "-c",
        "user.email=aiqa@example.invalid",
        "commit",
        "-q",
        "-m",
        "baseline",
    )

    hostile_bin = workspace / "bin"
    hostile_bin.mkdir()
    marker = tmp_path / "target-git-executed"
    hostile_git = hostile_bin / "git"
    hostile_git.write_text(
        f"#!/bin/sh\nprintf executed > {shlex.quote(str(marker))}\nexit 99\n",
        encoding="utf-8",
    )
    hostile_git.chmod(0o755)
    inherited = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{hostile_bin}{os.pathsep}{inherited}")

    inspector = RepositoryInspector(workspace)
    snapshot = inspector.snapshot()
    changes = inspector.change_set("HEAD")

    assert marker.exists() is False
    assert snapshot.git_sha is not None
    assert snapshot.fingerprint_complete is True
    assert "bin/git" in snapshot.changed_files
    assert changes.baseline_sha == snapshot.git_sha
    assert changes.head_sha == snapshot.git_sha
    assert "bin/git" in changes.worktree_files
