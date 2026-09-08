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
from ai_qa_automation.tools.repository import RepositoryInspector, RepositorySubjectError


def _require_git_authority() -> str:
    if not descriptor_relative_authority_supported():
        pytest.skip("descriptor-relative filesystem authority is unavailable")
    executable = shutil.which("git")
    if executable is None:
        pytest.skip("git executable is unavailable")
    return executable


def _init_repo(tmp_path: Path) -> Path:
    executable = _require_git_authority()
    repo = tmp_path / "repo"
    home = tmp_path / ".aiqa-ref-storage-git-home"
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
        [executable, "init", "-q", str(repo)],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git init failed: {result.stderr}")
    return repo


def _append_config(repo: Path, text: str) -> None:
    config = repo / ".git" / "config"
    with config.open("a", encoding="utf-8", newline="") as handle:
        handle.write(text)


def test_repository_accepts_explicit_in_tree_files_ref_storage(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    config = repo / ".git" / "config"
    current = config.read_text(encoding="utf-8")
    config.write_text(
        current.replace("repositoryformatversion = 0", "repositoryformatversion = 1")
        + '\n[extensions]\n\trefStorage = "files" # canonical in-tree backend\n',
        encoding="utf-8",
    )

    snapshot = RepositoryInspector(repo).snapshot()

    assert snapshot.fingerprint_complete is True


@pytest.mark.parametrize(
    "value",
    [
        "files:///tmp/external-refs",
        "files://../external-refs",
        "reftable:///tmp/external-refs",
        "postgres://127.0.0.1:5432/refs",
    ],
)
def test_repository_rejects_payload_backed_or_unknown_ref_storage(
    tmp_path: Path,
    value: str,
) -> None:
    repo = _init_repo(tmp_path)
    _append_config(repo, f"\n[extensions]\n\trefStorage = {value}\n")

    with pytest.raises(
        RepositorySubjectError,
        match=r"unsupported extensions.refStorage syntax or payload",
    ):
        RepositoryInspector(repo)


def test_repository_rejects_same_line_redirected_ref_storage(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _append_config(repo, "\n[extensions] refStorage = files:///tmp/external-refs\n")

    with pytest.raises(
        RepositorySubjectError,
        match=r"unsupported extensions.refStorage syntax or payload",
    ):
        RepositoryInspector(repo)


def test_repository_rejects_bom_prefixed_redirected_ref_storage(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    config = repo / ".git" / "config"
    config.write_bytes(
        b"\xef\xbb\xbf[extensions]\nrefStorage = files:///tmp/external-refs\n"
    )

    with pytest.raises(
        RepositorySubjectError,
        match=r"unsupported extensions.refStorage syntax or payload",
    ):
        RepositoryInspector(repo)


def test_repository_rejects_bom_prefixed_external_include(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    external = tmp_path / "external.config"
    external.write_text("[core]\nfilemode = false\n", encoding="utf-8")
    config = repo / ".git" / "config"
    config.write_bytes(
        b"\xef\xbb\xbf[include] path = "
        + str(external).encode("utf-8")
        + b"\n"
    )

    with pytest.raises(RepositorySubjectError, match="external configuration"):
        RepositoryInspector(repo)


def test_repository_rejects_ambiguous_ref_storage_assignments(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    _append_config(
        repo,
        "\n[extensions]\n\trefStorage = files\n\trefStorage = files\n",
    )

    with pytest.raises(RepositorySubjectError, match="ambiguous reference storage authority"):
        RepositoryInspector(repo)


def test_repository_rejects_worktree_ref_storage_override(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    (repo / ".git" / "config.worktree").write_text(
        "[extensions]\nrefStorage = files\n",
        encoding="utf-8",
    )

    with pytest.raises(RepositorySubjectError, match="worktree config must not override"):
        RepositoryInspector(repo)


def test_repository_still_rejects_canonical_reftable_backend(tmp_path: Path) -> None:
    executable = _require_git_authority()
    repo = tmp_path / "repo"
    home = tmp_path / ".aiqa-reftable-git-home"
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

    with pytest.raises(RepositorySubjectError, match="reftable ref storage"):
        RepositoryInspector(repo)


def test_repository_ref_storage_config_aba_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _init_repo(tmp_path)
    inspector = RepositoryInspector(repo)
    config = repo / ".git" / "config"
    original = config.read_bytes()
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
        calls += 1
        config.write_bytes(original + b"\n[extensions]\nrefStorage = files:///tmp/external-refs\n")
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
            config.write_bytes(original)

    monkeypatch.setattr(repository_module, "run_bounded_subprocess", aba_then_run)

    with pytest.raises(RepositorySubjectError, match="config authority changed"):
        inspector._git("rev-parse", "--show-object-format")

    assert calls == 1
    assert config.read_bytes() == original
