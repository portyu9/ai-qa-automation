from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.tools.repository import RepositoryInspector


def _init_repo(repo: Path) -> None:
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    home = repo.parent / ".aiqa-timeout-git-home"
    home.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    commands = (
        ("init", "-q"),
        ("config", "user.name", "AI QA Test"),
        ("config", "user.email", "aiqa@example.invalid"),
    )
    for args in commands:
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


def test_snapshot_marks_git_inspection_failure_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _init_repo(tmp_path)
    inspector = RepositoryInspector(tmp_path)

    def timeout(*args: str, **kwargs: object) -> str | None:
        raise RuntimeError("git command exceeded inspection budget")

    monkeypatch.setattr(inspector, "_git", timeout)

    snapshot = inspector.snapshot()

    assert snapshot.git_sha is None
    assert snapshot.fingerprint_complete is False
    assert snapshot.fingerprint_incomplete_reasons == ("git-inspection-timeout",)
    assert "INCOMPLETE" in snapshot.status


def test_repository_inspection_requires_positive_timeout(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        RepositoryInspector(tmp_path, timeout_seconds=0)
