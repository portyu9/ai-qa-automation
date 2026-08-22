from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import ai_qa_automation.tools.test_execution as execution_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.test_execution import TestRunner


def snapshot(
    *,
    fingerprint: str,
    git_sha: str | None = "a" * 40,
    complete: bool = True,
) -> SimpleNamespace:
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
    timed_out: bool = False,
) -> None:
    sequence = iter(snapshots)

    class FakeInspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self) -> object:
            return next(sequence)

    monkeypatch.setattr(execution_module, "RepositoryInspector", FakeInspector)
    monkeypatch.setattr(
        execution_module,
        "run_bounded_subprocess",
        lambda *args, **kwargs: BoundedSubprocessResult(
            returncode=returncode,
            stdout="1 passed",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=timed_out,
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


def test_pytest_timeout_maps_to_controlled_timeout_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_execution(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
        returncode=-9,
        timed_out=True,
    )
    runner = TestRunner(tmp_path, EvidenceStore(tmp_path / "artifacts", "run-timeout"))

    result = runner.run_pytest([])

    assert result.exit_code == 124
    assert "execution budget" in result.stderr


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5])
def test_pytest_runner_rejects_invalid_timeout_bound(tmp_path: Path, timeout: object) -> None:
    run_id = f"run-timeout-{str(timeout).replace('.', '-')}"
    with pytest.raises(ValueError, match="timeout_seconds"):
        TestRunner(
            tmp_path,
            EvidenceStore(tmp_path / "artifacts", run_id),
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )
