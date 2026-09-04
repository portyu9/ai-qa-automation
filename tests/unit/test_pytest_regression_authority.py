from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import ai_qa_automation.tools.pytest_regression as regression_module
from ai_qa_automation.evidence import EvidenceStore
from ai_qa_automation.tools.execution_env import BoundedSubprocessResult
from ai_qa_automation.tools.pytest_regression import (
    RegressionSuiteError,
    _bounded_config_options,
    _config,
    _conftests,
    _parse_collection,
    run_regression_pytest,
)
from ai_qa_automation.tools.pytest_sandbox import PytestSandboxPreflight
from ai_qa_automation.tools.test_execution import TestRunner


def _snapshot() -> SimpleNamespace:
    return SimpleNamespace(
        fingerprint="fp",
        git_sha="a" * 40,
        fingerprint_complete=True,
        fingerprint_incomplete_reasons=(),
    )


def _result(
    stdout: str,
    *,
    returncode: int = 0,
    stdout_truncated: bool = False,
) -> BoundedSubprocessResult:
    return BoundedSubprocessResult(
        returncode=returncode,
        stdout=stdout,
        stderr="",
        stdout_truncated=stdout_truncated,
        stderr_truncated=False,
        timed_out=False,
    )


class SequencedSandbox:
    python_executable = Path(sys.executable)

    def __init__(self, results: list[BoundedSubprocessResult]) -> None:
        self.results = list(results)
        self.workspace: Path | None = None
        self.source_workspace_hidden = False
        self.envs: list[dict[str, str]] = []
        self.commands: list[list[str]] = []
        self.preflight_result = PytestSandboxPreflight(
            ready=True,
            backend="fake-test-sandbox",
            reason=None,
            executable="/trusted/fake-sandbox",
            executable_sha256="sha256:" + "f" * 64,
            version="fake 1.0",
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
    ) -> SequencedSandbox:
        self.workspace = workspace.resolve()
        self.source_workspace_hidden = self.workspace != forbidden_source_workspace.resolve()
        return self

    def preflight(self) -> PytestSandboxPreflight:
        return self.preflight_result

    def run(
        self,
        command: list[str],
        *,
        env: dict[str, str],
        timeout_seconds: int | float,
    ) -> tuple[PytestSandboxPreflight, BoundedSubprocessResult]:
        assert timeout_seconds > 0
        self.commands.append(list(command))
        self.envs.append(dict(env))
        assert self.results
        return self.preflight_result, self.results.pop(0)


def _install_subject(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    pyproject: str | None = None,
    conftest: str | None = None,
) -> None:
    snapshots = iter([_snapshot(), _snapshot()])

    class Inspector:
        def __init__(self, _workspace: Path) -> None:
            pass

        def snapshot(self) -> object:
            return next(snapshots)

    @contextmanager
    def materialized(
        workspace: Path,
        *,
        expected_snapshot: object,
        scratch_root: Path,
        expected_scratch_root_identity: tuple[int, int],
    ):
        assert workspace
        assert expected_snapshot
        assert expected_scratch_root_identity
        root = scratch_root / "regression-subject"
        root.mkdir()
        tests = root / "tests"
        tests.mkdir()
        (tests / "test_a.py").write_text("def test_a():\n    assert True\n", encoding="utf-8")
        if pyproject is not None:
            (root / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        if conftest is not None:
            (root / "conftest.py").write_text(conftest, encoding="utf-8")
        yield SimpleNamespace(
            root=root,
            git_sha="a" * 40,
            source_fingerprint="fp",
            digest="sha256:" + "d" * 64,
        )

    monkeypatch.setattr(regression_module, "RepositoryInspector", Inspector)
    monkeypatch.setattr(regression_module, "materialized_pytest_execution_subject", materialized)


def _runner(
    tmp_path: Path,
    sandbox: SequencedSandbox,
    *,
    run_id: str,
) -> TestRunner:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return TestRunner(
        workspace,
        EvidenceStore(tmp_path / "artifacts", run_id),
        sandbox=sandbox,
    )


def test_regression_suite_reconciles_collection_execution_and_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = "tests/test_a.py::test_a"
    sandbox = SequencedSandbox(
        [
            _result(node + "\n"),
            _result(node + " PASSED\n"),
            _result(node + "\n"),
        ]
    )
    _install_subject(
        monkeypatch,
        tmp_path,
        pyproject=(
            "[tool.pytest.ini_options]\n"
            "testpaths = ['tests/smoke']\n"
            "addopts = \"-q -m 'not browser'\"\n"
        ),
        conftest="def pytest_collection_modifyitems(items):\n    return None\n",
    )
    runner = _runner(tmp_path, sandbox, run_id="run-regression-ok")

    result, suite = run_regression_pytest(runner, [])

    assert result.exit_code == 0
    assert suite is not None
    assert suite.pre_post_collection_match is True
    assert suite.execution_nodes_match is True
    assert suite.node_count == 1
    assert suite.config_path == "pyproject.toml"
    assert suite.config_options["testpaths"] == ["tests/smoke"]
    assert suite.config_options["addopts_tokens"] == ["-q", "-m", "not browser"]
    assert suite.conftest_count == 1
    assert suite.details()["testpaths_bypassed_by_explicit_root"] is True
    assert all(env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1" for env in sandbox.envs)
    assert len(sandbox.commands) == 3
    assert all(command[-1] == "." for command in sandbox.commands)


def test_regression_execution_node_mismatch_downgrades_zero_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = SequencedSandbox(
        [
            _result("tests/test_a.py::test_a\n"),
            _result("tests/test_other.py::test_other PASSED\n"),
        ]
    )
    _install_subject(monkeypatch, tmp_path)
    runner = _runner(tmp_path, sandbox, run_id="run-regression-mismatch")

    result, suite = run_regression_pytest(runner, [])

    assert result.exit_code == 125
    assert suite is not None
    assert suite.execution_nodes_match is False
    assert suite.pre_post_collection_match is False
    assert "regression-suite-integrity" in result.stderr


def test_regression_post_collection_mismatch_downgrades_zero_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    node = "tests/test_a.py::test_a"
    sandbox = SequencedSandbox(
        [
            _result(node + "\n"),
            _result(node + " PASSED\n"),
            _result(node + "\ntests/test_b.py::test_b\n"),
        ]
    )
    _install_subject(monkeypatch, tmp_path)
    runner = _runner(tmp_path, sandbox, run_id="run-regression-post-mismatch")

    result, suite = run_regression_pytest(runner, [])

    assert result.exit_code == 125
    assert suite is not None
    assert suite.execution_nodes_match is True
    assert suite.pre_post_collection_match is False


@pytest.mark.parametrize(
    "collection",
    [
        _result("", returncode=5),
        _result("tests/test_a.py::test_a\n", stdout_truncated=True),
    ],
)
def test_regression_unusable_collection_blocks_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    collection: BoundedSubprocessResult,
) -> None:
    sandbox = SequencedSandbox([collection])
    _install_subject(monkeypatch, tmp_path)
    runner = _runner(tmp_path, sandbox, run_id="run-regression-blocked")

    result, suite = run_regression_pytest(runner, [])

    assert result.exit_code == 126
    assert result.execution_started is False
    assert suite is None
    assert len(sandbox.commands) == 1


def test_collection_parser_rejects_empty_truncated_and_duplicate_manifests() -> None:
    with pytest.raises(RegressionSuiteError, match="no runnable"):
        _parse_collection("", truncated=False)
    with pytest.raises(RegressionSuiteError, match="byte bound"):
        _parse_collection("tests/test_a.py::test_a\n", truncated=True)
    with pytest.raises(RegressionSuiteError, match="duplicate"):
        _parse_collection(
            "tests/test_a.py::test_a\ntests/test_a.py::test_a\n",
            truncated=False,
        )


def test_config_precedence_and_selection_semantics_are_bound(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = \"-k smoke\"\n",
        encoding="utf-8",
    )
    (tmp_path / "pytest.ini").write_text(
        "[pytest]\naddopts = -m integration\n",
        encoding="utf-8",
    )

    observed = _config(tmp_path)

    assert observed.path == "pytest.ini"
    assert observed.options["addopts_tokens"] == ["-m", "integration"]


def test_config_addopts_cannot_redirect_admitted_config() -> None:
    with pytest.raises(RegressionSuiteError, match="redirect"):
        _bounded_config_options({"addopts": "-c other.ini"})


def test_conftest_digest_changes_with_hook_bytes(tmp_path: Path) -> None:
    path = tmp_path / "conftest.py"
    path.write_text("def pytest_ignore_collect(path):\n    return False\n", encoding="utf-8")
    first_count, first_digest, _ = _conftests(tmp_path)
    path.write_text("def pytest_ignore_collect(path):\n    return True\n", encoding="utf-8")
    second_count, second_digest, _ = _conftests(tmp_path)

    assert first_count == second_count == 1
    assert first_digest != second_digest
