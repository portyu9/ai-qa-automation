from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

import ai_qa_automation.tools.repository as repository_module
from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.repository import RepositoryInspector


def _require_descriptor_authority() -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")


def _git(repo: Path, *args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-head-ref-authority-git-home"
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


def _init_same_tree_divergent_ancestry(repo: Path) -> tuple[str, str, str, str]:
    _require_descriptor_authority()
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    x = repo / "x.txt"
    y = repo / "y.txt"
    x.write_text("0\n", encoding="utf-8")
    y.write_text("0\n", encoding="utf-8")
    _git(repo, "add", "--", "x.txt", "y.txt")
    _git(repo, "commit", "-q", "-m", "root")
    root = _git(repo, "rev-parse", "HEAD")

    _git(repo, "switch", "-q", "-c", "baseline")
    x.write_text("1\n", encoding="utf-8")
    _git(repo, "add", "--", "x.txt")
    _git(repo, "commit", "-q", "-m", "baseline x")
    baseline = _git(repo, "rev-parse", "HEAD")

    _git(repo, "switch", "-q", "-c", "fake")
    y.write_text("1\n", encoding="utf-8")
    _git(repo, "add", "--", "y.txt")
    _git(repo, "commit", "-q", "-m", "fake y")
    fake = _git(repo, "rev-parse", "HEAD")

    _git(repo, "switch", "-q", "-c", "actual", root)
    x.write_text("1\n", encoding="utf-8")
    y.write_text("1\n", encoding="utf-8")
    _git(repo, "add", "--", "x.txt", "y.txt")
    _git(repo, "commit", "-q", "-m", "actual x and y")
    actual = _git(repo, "rev-parse", "HEAD")

    assert _git(repo, "rev-parse", f"{actual}^{{tree}}") == _git(
        repo, "rev-parse", f"{fake}^{{tree}}"
    )
    assert _git(repo, "merge-base", baseline, actual) == root
    assert _git(repo, "merge-base", baseline, fake) == baseline
    return root, baseline, actual, fake


def test_change_set_fails_closed_on_current_head_ref_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    _root, _baseline, actual, fake = _init_same_tree_divergent_ancestry(repo)
    inspector = RepositoryInspector(repo)
    expected = inspector.change_set("baseline")
    assert expected.head_sha == actual
    assert expected.committed_files == ("x.txt", "y.txt")

    actual_ref = repo / ".git" / "refs" / "heads" / "actual"
    original = actual_ref.read_bytes()
    assert original.strip().decode("ascii") == actual
    real_run = repository_module.run_bounded_subprocess
    head_calls = 0

    def aba_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedSubprocessResult:
        nonlocal head_calls
        if list(command[-2:]) != ["rev-parse", "HEAD"]:
            return real_run(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                pass_fds=pass_fds,
            )
        head_calls += 1
        actual_ref.write_text(f"{fake}\n", encoding="ascii")
        try:
            return real_run(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                pass_fds=pass_fds,
            )
        finally:
            actual_ref.write_bytes(original)

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", aba_then_run)

    with pytest.raises(RuntimeError, match="Git HEAD metadata changed during resolution"):
        inspector.change_set("baseline")

    assert head_calls == 1
    assert actual_ref.read_bytes() == original
    assert _git(repo, "rev-parse", "HEAD") == actual


def test_snapshot_accepts_stable_detached_head(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _root, _baseline, actual, _fake = _init_same_tree_divergent_ancestry(repo)
    _git(repo, "switch", "-q", "--detach", actual)

    snapshot = RepositoryInspector(repo).snapshot()

    assert snapshot.git_sha == actual
    assert snapshot.branch is None
    assert snapshot.changed_files == ()
    assert snapshot.fingerprint_complete is True


def test_snapshot_accepts_stable_unborn_symbolic_head(tmp_path: Path) -> None:
    _require_descriptor_authority()
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")

    snapshot = RepositoryInspector(repo).snapshot()

    assert snapshot.git_sha is None
    assert snapshot.branch
    assert snapshot.changed_files == ()
    assert snapshot.fingerprint_complete is True
