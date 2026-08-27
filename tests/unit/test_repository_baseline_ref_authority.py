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
    home = repo.parent / ".aiqa-baseline-ref-authority-git-home"
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


def _init_two_commit_repo(repo: Path) -> tuple[str, str]:
    _require_descriptor_authority()
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "AI QA Test")
    _git(repo, "config", "user.email", "aiqa@example.invalid")
    tracked = repo / "tracked.txt"
    tracked.write_text("baseline\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "baseline")
    baseline = _git(repo, "rev-parse", "HEAD")
    _git(repo, "branch", "baseline", baseline)
    tracked.write_text("head\n", encoding="utf-8")
    _git(repo, "add", "--", "tracked.txt")
    _git(repo, "commit", "-q", "-m", "head")
    head = _git(repo, "rev-parse", "HEAD")
    assert head != baseline
    return baseline, head


def _swap_loose_baseline_ref_during_resolution(
    repo: Path,
    head: str,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, bytes, list[int]]:
    ref_path = repo / ".git" / "refs" / "heads" / "baseline"
    original = ref_path.read_bytes()
    calls = [0]
    real_run = repository_module.run_bounded_subprocess

    def aba_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedSubprocessResult:
        if list(command[-3:]) != ["rev-parse", "--verify", "baseline^{commit}"]:
            return real_run(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                pass_fds=pass_fds,
            )
        calls[0] += 1
        ref_path.write_text(f"{head}\n", encoding="ascii")
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
            ref_path.write_bytes(original)

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", aba_then_run)
    return ref_path, original, calls


def test_change_set_fails_closed_on_loose_baseline_ref_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    baseline, head = _init_two_commit_repo(repo)
    ref_path, original, calls = _swap_loose_baseline_ref_during_resolution(
        repo,
        head,
        monkeypatch,
    )

    with pytest.raises(RuntimeError, match="baseline ref metadata changed during resolution"):
        RepositoryInspector(repo).change_set("baseline")

    assert calls == [1]
    assert ref_path.read_bytes() == original
    assert _git(repo, "rev-parse", "baseline") == baseline


def test_change_set_fails_closed_on_packed_baseline_ref_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    baseline, head = _init_two_commit_repo(repo)
    _git(repo, "pack-refs", "--all", "--prune")
    loose_ref = repo / ".git" / "refs" / "heads" / "baseline"
    assert not loose_ref.exists()
    packed_refs = repo / ".git" / "packed-refs"
    original = packed_refs.read_bytes()
    baseline_record = f"{baseline} refs/heads/baseline\n".encode("ascii")
    head_record = f"{head} refs/heads/baseline\n".encode("ascii")
    assert baseline_record in original
    transient = original.replace(baseline_record, head_record, 1)
    assert transient != original
    assert len(transient) == len(original)

    real_run = repository_module.run_bounded_subprocess
    calls = 0

    def aba_then_run(
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout_seconds: int | float,
        max_output_bytes: int = 2_000_000,
        pass_fds: Sequence[int] = (),
    ) -> BoundedSubprocessResult:
        nonlocal calls
        if list(command[-3:]) != [
            "rev-parse",
            "--verify",
            "refs/heads/baseline^{commit}",
        ]:
            return real_run(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                pass_fds=pass_fds,
            )
        calls += 1
        packed_refs.write_bytes(transient)
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
            packed_refs.write_bytes(original)

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", aba_then_run)

    with pytest.raises(RuntimeError, match="baseline ref metadata changed during resolution"):
        RepositoryInspector(repo).change_set("refs/heads/baseline")

    assert calls == 1
    assert packed_refs.read_bytes() == original
    assert _git(repo, "rev-parse", "refs/heads/baseline") == baseline


def test_change_set_accepts_stable_short_full_and_oid_baselines(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    baseline, _head = _init_two_commit_repo(repo)
    inspector = RepositoryInspector(repo)

    short = inspector.change_set("baseline")
    full = inspector.change_set("refs/heads/baseline")
    immutable = inspector.change_set(baseline)

    for change_set in (short, full, immutable):
        assert change_set.baseline_sha == baseline
        assert change_set.committed_files == ("tracked.txt",)
        assert change_set.changed_files == ("tracked.txt",)


def test_change_set_rejects_revision_expression_baseline(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _init_two_commit_repo(repo)

    with pytest.raises(ValueError, match="baseline ref"):
        RepositoryInspector(repo).change_set("baseline~1")
