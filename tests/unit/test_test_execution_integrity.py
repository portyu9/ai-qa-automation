from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import ai_qa_automation.tools.test_execution as execution_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.pytest_sandbox import (
    PytestSandboxExecutionUnverified,
    PytestSandboxPreflight,
    PytestSandboxUnavailable,
)
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


class FakeSandbox:
    python_executable = Path(sys.executable)

    def __init__(self, *, returncode: int = 0, timed_out: bool = False) -> None:
        self.workspace: Path | None = None
        self.forbidden_source_workspace: Path | None = None
        self.source_workspace_hidden = False
        self.result = BoundedSubprocessResult(
            returncode=returncode,
            stdout="1 passed",
            stderr="",
            stdout_truncated=False,
            stderr_truncated=False,
            timed_out=timed_out,
        )
        self.preflight_result = PytestSandboxPreflight(
            ready=True,
            backend="fake-test-sandbox",
            reason=None,
            executable="/trusted/fake-sandbox",
            executable_sha256="sha256:" + "a" * 64,
            version="fake 1.0",
            parent_namespaces={"mnt": "a", "pid": "b", "net": "c", "user": "d"},
            child_namespaces={"mnt": "e", "pid": "f", "net": "g", "user": "h"},
            workspace_identity_bound=True,
            workspace_read_only=True,
            forbidden_roots_hidden=True,
            no_non_loopback_interfaces=True,
            effective_capabilities_zero=True,
        )

    def for_materialized_workspace(
        self,
        workspace: Path,
        *,
        forbidden_source_workspace: Path,
    ) -> FakeSandbox:
        self.workspace = workspace.resolve()
        self.forbidden_source_workspace = forbidden_source_workspace.resolve()
        self.source_workspace_hidden = self.workspace != self.forbidden_source_workspace
        return self

    def preflight(self) -> PytestSandboxPreflight:
        return self.preflight_result

    def run(self, command, *, env, timeout_seconds):
        return self.preflight_result, self.result


class BlockedSandbox(FakeSandbox):
    def __init__(self) -> None:
        super().__init__()
        self.preflight_result = PytestSandboxPreflight(
            ready=False,
            backend="bubblewrap",
            reason="Bubblewrap executable is unavailable",
        )

    def run(self, command, *, env, timeout_seconds):
        raise PytestSandboxUnavailable(self.preflight_result)


class PostflightUnverifiedSandbox(FakeSandbox):
    def run(self, command, *, env, timeout_seconds):
        raise PytestSandboxExecutionUnverified(
            self.preflight_result,
            self.result,
            "sandbox executable changed after child execution",
        )


def install_fake_snapshots(
    monkeypatch: pytest.MonkeyPatch,
    snapshots: list[object],
) -> None:
    sequence = iter(snapshots)

    class FakeInspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self) -> object:
            return next(sequence)

    @contextmanager
    def fake_materialized_subject(
        workspace: Path,
        *,
        expected_snapshot: object,
        scratch_root: Path,
        expected_scratch_root_identity: tuple[int, int],
    ):
        assert expected_scratch_root_identity
        root = scratch_root / "fake-materialized-pytest-subject"
        root.mkdir(exist_ok=True)
        yield SimpleNamespace(
            root=root,
            details=lambda: {
                "git_sha": getattr(expected_snapshot, "git_sha", None),
                "source_fingerprint": getattr(expected_snapshot, "fingerprint", None),
                "digest": "sha256:" + "f" * 64,
                "file_count": 1,
                "total_bytes": 1,
                "ignored_inputs_excluded": True,
                "git_metadata_excluded": True,
            },
        )

    monkeypatch.setattr(execution_module, "RepositoryInspector", FakeInspector)
    monkeypatch.setattr(
        execution_module,
        "materialized_pytest_execution_subject",
        fake_materialized_subject,
    )


def test_pytest_zero_exit_requires_unchanged_complete_git_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
    )
    runner = TestRunner(
        tmp_path / "workspace",
        EvidenceStore(tmp_path / "artifacts", "run-ok"),
        sandbox=FakeSandbox(),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 0
    assert result.execution_started is True
    assert result.block_reason is None
    assert "workspace-integrity" not in result.stderr


def test_pytest_zero_exit_is_downgraded_when_test_changes_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [snapshot(fingerprint="before"), snapshot(fingerprint="after")],
    )
    runner = TestRunner(
        tmp_path / "workspace",
        EvidenceStore(tmp_path / "artifacts", "run-drift"),
        sandbox=FakeSandbox(),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "target workspace changed during pytest execution" in result.stderr


def test_pytest_without_git_provenance_is_blocked_before_target_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [
            snapshot(fingerprint="fp", git_sha=None),
            snapshot(fingerprint="fp", git_sha=None),
        ],
    )
    runner = TestRunner(
        tmp_path / "workspace",
        EvidenceStore(tmp_path / "artifacts", "run-nongit"),
        sandbox=FakeSandbox(),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 126
    assert result.execution_started is False
    assert "requires a Git-backed target workspace" in result.stderr


def test_pytest_zero_exit_is_downgraded_when_fingerprint_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [
            snapshot(fingerprint="fp", complete=True),
            snapshot(fingerprint="fp", complete=False),
        ],
    )
    runner = TestRunner(
        tmp_path / "workspace",
        EvidenceStore(tmp_path / "artifacts", "run-incomplete"),
        sandbox=FakeSandbox(),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "workspace fingerprint is incomplete" in result.stderr


def test_pytest_timeout_maps_to_controlled_timeout_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
    )
    runner = TestRunner(
        tmp_path / "workspace",
        EvidenceStore(tmp_path / "artifacts", "run-timeout"),
        sandbox=FakeSandbox(returncode=-9, timed_out=True),
    )

    result = runner.run_pytest([])

    assert result.exit_code == 124
    assert "execution budget" in result.stderr


@pytest.mark.parametrize("timeout", [0, -1, True, 1.5])
def test_pytest_runner_rejects_invalid_timeout_bound(tmp_path: Path, timeout: object) -> None:
    run_id = f"run-timeout-{str(timeout).replace('.', '-')}"
    with pytest.raises(ValueError, match="timeout_seconds"):
        TestRunner(
            tmp_path / "workspace",
            EvidenceStore(tmp_path / "artifacts", run_id),
            timeout_seconds=timeout,  # type: ignore[arg-type]
            sandbox=FakeSandbox(),
        )


def test_direct_test_runner_has_no_unsandboxed_fallback_when_backend_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
    )
    evidence = EvidenceStore(tmp_path / "artifacts", "run-sandbox-blocked")
    runner = TestRunner(tmp_path / "workspace", evidence, sandbox=BlockedSandbox())

    result = runner.run_pytest([])

    assert result.exit_code == 126
    assert result.execution_started is False
    assert result.block_reason == "Bubblewrap executable is unavailable"
    assert result.stdout == ""
    assert "Bubblewrap executable is unavailable" in result.stderr
    exit_item = evidence.get(result.evidence_ids[0])
    assert exit_item.structured_data["sandbox"]["execution_started"] is False
    assert exit_item.structured_data["sandbox"]["ready"] is False
    assert exit_item.structured_data["sandbox"]["postflight_verified"] is False
    assert exit_item.structured_data["sandbox"]["cpu_limit_seconds"] is None


def test_sandbox_postflight_uncertainty_invalidates_zero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    install_fake_snapshots(
        monkeypatch,
        [snapshot(fingerprint="fp"), snapshot(fingerprint="fp")],
    )
    evidence = EvidenceStore(tmp_path / "artifacts", "run-sandbox-postflight")
    runner = TestRunner(tmp_path / "workspace", evidence, sandbox=PostflightUnverifiedSandbox())

    result = runner.run_pytest([])

    assert result.exit_code == 125
    assert "sandbox-integrity" in result.stderr
    exit_item = evidence.get(result.evidence_ids[0])
    assert exit_item.structured_data["sandbox"]["execution_started"] is True
    assert exit_item.structured_data["sandbox"]["postflight_verified"] is False
