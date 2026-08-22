from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

import pytest

import ai_qa_automation.tools.test_execution as execution_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.test_execution import TestRunner


def snapshot(*, fingerprint: str, git_sha: str | None = "a" * 40, complete: bool = True):
    return SimpleNamespace(
        fingerprint=fingerprint,
        git_sha=git_sha,
        fingerprint_complete=complete,
        fingerprint_incomplete_reasons=() if complete else ("changed-file-unreadable",),
    )


def install_fake_execution(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[object],
    *,
    returncode: int = 0,
) -> None:
    sequence = iter(snapshots)

    class FakeInspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self):
            return next(sequence)

    monkeypatch.setattr(execution_module, "RepositoryInspector", FakeInspector)
    monkeypatch.setattr(
        execution_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=returncode,
            stdout="1 passed",
            stderr="",
        ),
    )


def test_pytest_zero_exit_requires_unchanged_complete_git_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_execution(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
    )
    runner = TestRunner(tmp_path, EvidenceStore(tmp_path / "artifacts", "run-ok"))

    result = runner.run_pytest([])

    assert result.exit_code == 0
    assert "workspace-integrity" not in result.stderr


def test_pytest_zero_exit_is_downgraded_when_test_changes_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_execution(
        monkeypatch,
        [snapshot(fingerprint="before"), snapshot(fingerprint="after")],
    )
    runner = TestRunner(tmp_path, EvidenceStore(tmp_path / "artifacts", "run-drift"))

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "target workspace changed during pytest execution" in result.stderr


def test_pytest_zero_exit_is_downgraded_without_git_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_execution(
        monkeypatch,
        [
            snapshot(fingerprint="fp", git_sha=None),
            snapshot(fingerprint="fp", git_sha=None),
        ],
    )
    runner = TestRunner(tmp_path, EvidenceStore(tmp_path / "artifacts", "run-nongit"))

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "requires a Git-backed target workspace" in result.stderr


def test_pytest_zero_exit_is_downgraded_when_fingerprint_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_execution(
        monkeypatch,
        [
            snapshot(fingerprint="fp", complete=True),
            snapshot(fingerprint="fp", complete=False),
        ],
    )
    runner = TestRunner(tmp_path, EvidenceStore(tmp_path / "artifacts", "run-incomplete"))

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "workspace fingerprint is incomplete" in result.stderr


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5])
def test_pytest_runner_rejects_invalid_timeout_bound(tmp_path: Path, timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        TestRunner(
            tmp_path,
            EvidenceStore(tmp_path / "artifacts", f"run-timeout-{str(timeout).replace('.', '-') }"),
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )
