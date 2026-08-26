from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ai_qa_automation.fs_authority import descriptor_relative_authority_supported
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


def test_repository_rejects_unbound_reftable_ref_storage(tmp_path: Path) -> None:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")

    repo = tmp_path / "repo"
    home = tmp_path / ".aiqa-reftable-authority-git-home"
    home.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    result = subprocess.run(
        [executable, "init", "-q", "--ref-format=reftable", str(repo)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("installed Git does not support reftable repository initialization")

    assert (repo / ".git" / "reftable").is_dir()
    with pytest.raises(RepositorySubjectError, match="reftable ref storage"):
        RepositoryInspector(repo)
