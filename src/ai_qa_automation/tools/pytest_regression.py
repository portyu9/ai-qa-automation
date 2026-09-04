from __future__ import annotations

import configparser
import hashlib
import importlib.metadata
import json
import re
import shlex
import stat
import tempfile
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from ..models import EvidenceItem, EvidenceKind, EvidenceNature
from ..redaction import redact_text
from .artifacts import text_artifact
from .execution_env import BoundedSubprocessResult, restricted_subprocess_env
from .execution_subject import ExecutionSubjectError, materialized_pytest_execution_subject
from .pytest_sandbox import (
    PytestSandboxExecutionUnverified,
    PytestSandboxPreflight,
    PytestSandboxUnavailable,
)
from .repository import RepositoryInspector
from .test_execution import TestExecutionResult, TestRunner

_MAX_ITEMS = 10_000
_MAX_NODE_BYTES = 4_096
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_CONFIG_BYTES = 1_000_000
_MAX_CONFIG_EVIDENCE_BYTES = 64_000
_MAX_CONFTEST_FILES = 2_000
_MAX_CONFTEST_BYTES = 512_000
_EXECUTION_RE = re.compile(r"^(?P<node>.+?)\s+(?:PASSED|SKIPPED|XFAIL|XPASS)(?:\s|$)")
_SKIP_RE = re.compile(r"^SKIPPED \[\d+\] .+$")


class RegressionSuiteError(RuntimeError):
    """Raised when full-regression suite authority cannot be proven."""


@dataclass(frozen=True, slots=True)
class RegressionSuiteIdentity:
    suite_id: str
    git_sha: str
    source_fingerprint: str
    execution_subject_digest: str
    pytest_version: str
    node_count: int
    nodeids_sha256: str
    config_path: str | None
    config_sha256: str | None
    config_options: dict[str, object]
    conftest_count: int
    conftest_sha256: str
    manifest_artifact: str
    pre_post_collection_match: bool
    execution_nodes_match: bool

    def details(self) -> dict[str, object]:
        return {
            "suite_id": self.suite_id,
            "git_sha": self.git_sha,
            "source_fingerprint": self.source_fingerprint,
            "execution_subject_digest": self.execution_subject_digest,
            "pytest_version": self.pytest_version,
            "node_count": self.node_count,
            "nodeids_sha256": self.nodeids_sha256,
            "config_path": self.config_path,
            "config_sha256": self.config_sha256,
            "config_options": dict(self.config_options),
            "conftest_count": self.conftest_count,
            "conftest_sha256": self.conftest_sha256,
            "manifest_artifact": self.manifest_artifact,
            "pre_post_collection_match": self.pre_post_collection_match,
            "execution_nodes_match": self.execution_nodes_match,
            "execution_root": ".",
            "testpaths_bypassed_by_explicit_root": True,
        }


@dataclass(frozen=True, slots=True)
class _Collection:
    nodeids: tuple[str, ...]
    skipped: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Config:
    path: str | None
    sha256: str | None
    options: dict[str, object]


def _safe_node(node: str) -> str:
    if not node or len(node.encode()) > _MAX_NODE_BYTES or "\x00" in node:
        raise RegressionSuiteError("pytest produced an invalid or oversized node id")
    path = PurePosixPath(node.split("::", 1)[0])
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RegressionSuiteError("pytest produced an unsafe node id")
    return node


def _parse_collection(stdout: str, *, truncated: bool) -> _Collection:
    if truncated:
        raise RegressionSuiteError("pytest collection output exceeded its byte bound")
    nodes: list[str] = []
    skipped: list[str] = []
    seen: set[str] = set()
    node_bytes = 0
    for raw in stdout.splitlines():
        line = raw.strip()
        if "::" in line:
            node = _safe_node(line)
            if node in seen:
                raise RegressionSuiteError("pytest collection produced duplicate node ids")
            seen.add(node)
            nodes.append(node)
            node_bytes += len(node.encode()) + 1
            if len(nodes) > _MAX_ITEMS or node_bytes > _MAX_MANIFEST_BYTES:
                raise RegressionSuiteError("pytest collection exceeded its deterministic bound")
        elif _SKIP_RE.match(line):
            if len(line.encode()) > _MAX_NODE_BYTES:
                raise RegressionSuiteError("pytest collection skip evidence exceeded its byte bound")
            skipped.append(line)
            if len(skipped) > _MAX_ITEMS:
                raise RegressionSuiteError("pytest collection skip evidence exceeded its item bound")
    if not nodes:
        raise RegressionSuiteError("pytest regression collection produced no runnable test items")
    return _Collection(tuple(nodes), tuple(skipped))


def _parse_execution_nodes(stdout: str, *, truncated: bool) -> tuple[str, ...]:
    if truncated:
        raise RegressionSuiteError("pytest execution output exceeded its reconciliation bound")
    nodes: list[str] = []
    seen: set[str] = set()
    total = 0
    for raw in stdout.splitlines():
        match = _EXECUTION_RE.match(raw.strip())
        if match is None:
            continue
        node = _safe_node(match.group("node"))
        if node in seen:
            raise RegressionSuiteError("pytest execution reported a duplicate terminal node id")
        seen.add(node)
        nodes.append(node)
        total += len(node.encode()) + 1
        if len(nodes) > _MAX_ITEMS or total > _MAX_MANIFEST_BYTES:
            raise RegressionSuiteError("pytest execution reconciliation exceeded its deterministic bound")
    return tuple(nodes)


def _read_regular(path: Path, *, label: str, max_bytes: int = _MAX_CONFIG_BYTES) -> bytes:
    try:
        observed = path.lstat()
    except OSError as exc:
        raise RegressionSuiteError(f"{label} could not be observed safely") from exc
    if not stat.S_ISREG(observed.st_mode) or observed.st_size > max_bytes:
        raise RegressionSuiteError(f"{label} is not an admitted bounded regular file")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RegressionSuiteError(f"{label} could not be read safely") from exc
    if len(data) != observed.st_size:
        raise RegressionSuiteError(f"{label} changed during observation")
    return data


def _ini(data: bytes, section: str, label: str) -> dict[str, object]:
    parser = configparser.RawConfigParser(interpolation=None)
    try:
        parser.read_string(data.decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise RegressionSuiteError(f"{label} is malformed") from exc
    return dict(parser.items(section)) if parser.has_section(section) else {}


def _toml(data: bytes, label: str) -> dict[str, Any]:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RegressionSuiteError(f"{label} is malformed") from exc


def _config_table(name: str, data: bytes) -> tuple[bool, dict[str, object]]:
    if name in {"pytest.toml", ".pytest.toml"}:
        table = _toml(data, name).get("pytest")
        return True, dict(table) if isinstance(table, dict) else {}
    if name in {"pytest.ini", ".pytest.ini"}:
        return True, _ini(data, "pytest", name)
    if name == "pyproject.toml":
        loaded = _toml(data, name)
        tool = loaded.get("tool")
        pytest_table = tool.get("pytest") if isinstance(tool, dict) else None
        if not isinstance(pytest_table, dict):
            return False, {}
        result = {key: value for key, value in pytest_table.items() if key != "ini_options"}
        ini_options = pytest_table.get("ini_options")
        if isinstance(ini_options, dict):
            result.update(ini_options)
        return True, result
    if name == "tox.ini":
        table = _ini(data, "pytest", name)
        return bool(table), table
    if name == "setup.cfg":
        table = _ini(data, "tool:pytest", name)
        return bool(table), table
    return False, {}


def _config(root: Path) -> _Config:
    candidates = (
        "pytest.toml",
        ".pytest.toml",
        "pytest.ini",
        ".pytest.ini",
        "pyproject.toml",
        "tox.ini",
        "setup.cfg",
    )
    pyproject_fallback: tuple[str, bytes] | None = None
    for name in candidates:
        path = root / name
        if not path.exists():
            continue
        data = _read_regular(path, label=f"pytest config {name}")
        if name == "pyproject.toml":
            pyproject_fallback = (name, data)
        matched, table = _config_table(name, data)
        if not matched:
            continue
        options = _bounded_config_options(table)
        return _Config(name, hashlib.sha256(data).hexdigest(), options)
    if pyproject_fallback is not None:
        name, data = pyproject_fallback
        return _Config(name, hashlib.sha256(data).hexdigest(), {})
    return _Config(None, None, {})


def _bounded_config_options(table: dict[str, object]) -> dict[str, object]:
    keys = (
        "addopts",
        "testpaths",
        "python_files",
        "python_classes",
        "python_functions",
        "norecursedirs",
        "required_plugins",
    )
    result: dict[str, object] = {}
    for key in keys:
        value = table.get(key)
        if isinstance(value, (str, bool, int, float)) or value is None:
            if key in table:
                result[key] = value.strip() if isinstance(value, str) else value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            result[key] = list(value)
    addopts = result.get("addopts")
    if isinstance(addopts, str):
        try:
            tokens = shlex.split(addopts)
        except ValueError as exc:
            raise RegressionSuiteError("pytest addopts could not be tokenized") from exc
        result["addopts_tokens"] = tokens
        if any(
            token in {"-c", "--config-file"} or token.startswith("--config-file=")
            for token in tokens
        ):
            raise RegressionSuiteError("pytest addopts cannot redirect the admitted config file")
    elif isinstance(addopts, list):
        result["addopts_tokens"] = list(addopts)
    rendered = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(rendered.encode()) > _MAX_CONFIG_EVIDENCE_BYTES:
        raise RegressionSuiteError("pytest config semantics exceeded their evidence bound")
    return result


def _conftests(root: Path) -> tuple[int, str, tuple[tuple[str, str], ...]]:
    rows: list[tuple[str, str]] = []
    total = 0
    for path in sorted(root.rglob("conftest.py")):
        if len(rows) >= _MAX_CONFTEST_FILES:
            raise RegressionSuiteError("pytest conftest provenance exceeded its file bound")
        relative = path.relative_to(root).as_posix()
        data = _read_regular(path, label="pytest conftest")
        digest = hashlib.sha256(data).hexdigest()
        total += len(relative.encode()) + len(digest) + 8
        if total > _MAX_CONFTEST_BYTES:
            raise RegressionSuiteError("pytest conftest provenance exceeded its byte bound")
        rows.append((relative, digest))
    rendered = json.dumps(rows, separators=(",", ":"), ensure_ascii=False)
    return len(rows), hashlib.sha256(rendered.encode()).hexdigest(), tuple(rows)


def _run_phase(
    runner: TestRunner,
    sandbox: Any,
    command: list[str],
    *,
    env: dict[str, str],
    started: float,
) -> tuple[PytestSandboxPreflight, BoundedSubprocessResult]:
    remaining = float(runner.timeout_seconds) - (time.monotonic() - started)
    if remaining <= 0:
        raise RegressionSuiteError("pytest regression authority exhausted its shared timeout")
    try:
        return sandbox.run(command, env=env, timeout_seconds=remaining)
    except PytestSandboxUnavailable as exc:
        raise RegressionSuiteError(exc.preflight.reason or "pytest sandbox is unavailable") from exc
    except PytestSandboxExecutionUnverified as exc:
        raise RegressionSuiteError(exc.reason) from exc
    except (OSError, RuntimeError, ValueError) as exc:
        raise RegressionSuiteError(f"pytest sandbox failed with {type(exc).__name__}") from exc


def _blocked(
    runner: TestRunner,
    logical: list[str],
    started: float,
    reason: str,
) -> TestExecutionResult:
    safe = redact_text(reason)
    artifact, digest = text_artifact(
        runner.evidence,
        f"pytest/{uuid4().hex}.log",
        f"$ {' '.join(logical)}\n\nSTDERR\n{safe}\n",
        originating_tool="pytest",
    )
    item = runner.evidence.add(
        EvidenceItem(
            run_id=runner.evidence.run_id,
            kind=EvidenceKind.EXCEPTION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="pytest_regression_authority",
            summary="pytest full-regression suite authority was blocked",
            structured_data={"reason": safe, "execution_started": False},
            artifact_reference=artifact,
            content_hash=digest,
        )
    )
    return TestExecutionResult(
        command=tuple(logical),
        exit_code=126,
        stdout="",
        stderr=safe,
        duration_seconds=time.monotonic() - started,
        evidence_ids=(item.id,),
        execution_started=False,
        block_reason=safe,
    )


def run_regression_pytest(
    runner: TestRunner,
    requested_args: list[str],
) -> tuple[TestExecutionResult, RegressionSuiteIdentity | None]:
    """Run one full-regression suite with bounded collection/execution reconciliation."""

    safe_args = runner._validate_pytest_args(requested_args)
    logical = ["python", "-m", "pytest", *safe_args, "."]
    started = time.monotonic()
    before = RepositoryInspector(runner.workspace).snapshot()
    integrity = runner._workspace_integrity_failure(before, before)
    if integrity is not None:
        return _blocked(runner, logical, started, integrity), None

    try:
        scratch, scratch_identity = runner._trusted_scratch_root()
        with materialized_pytest_execution_subject(
            runner.workspace,
            expected_snapshot=before,
            scratch_root=scratch,
            expected_scratch_root_identity=scratch_identity,
        ) as subject:
            config = _config(subject.root)
            conftest_count, conftest_sha, conftest_rows = _conftests(subject.root)
            sandbox = runner._sandbox_for_materialized_workspace(subject.root)
            with tempfile.TemporaryDirectory(prefix="aiqa-pytest-home-", dir=scratch) as home:
                env = restricted_subprocess_env(
                    home=Path(home),
                    extra={
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                )
                python = str(sandbox.python_executable)
                common = [*safe_args, "--rootdir=.", "--capture=fd", "--color=no"]
                collect_cmd = [
                    python,
                    "-m",
                    "pytest",
                    *common,
                    "--collect-only",
                    "--verbosity=-1",
                    "-ra",
                    ".",
                ]
                preflight, pre_raw = _run_phase(
                    runner,
                    sandbox,
                    collect_cmd,
                    env=env,
                    started=started,
                )
                if pre_raw.timed_out or pre_raw.returncode != 0:
                    raise RegressionSuiteError(
                        "pytest regression collection did not complete successfully"
                    )
                pre = _parse_collection(pre_raw.stdout, truncated=pre_raw.stdout_truncated)

                pytest_version = importlib.metadata.version("pytest")
                manifest_payload = {
                    "schema_version": 1,
                    "git_sha": subject.git_sha,
                    "source_fingerprint": subject.source_fingerprint,
                    "execution_subject_digest": subject.digest,
                    "pytest_version": pytest_version,
                    "requested_args": safe_args,
                    "execution_root": ".",
                    "config": {
                        "path": config.path,
                        "sha256": config.sha256,
                        "options": config.options,
                    },
                    "conftests": [
                        {"path": path, "sha256": digest}
                        for path, digest in conftest_rows
                    ],
                    "collection": {
                        "nodeids": list(pre.nodeids),
                        "skipped": list(pre.skipped),
                    },
                }
                manifest_json = json.dumps(
                    manifest_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                manifest_limit = (
                    _MAX_MANIFEST_BYTES + _MAX_CONFTEST_BYTES + _MAX_CONFIG_EVIDENCE_BYTES
                )
                if len(manifest_json.encode()) > manifest_limit:
                    raise RegressionSuiteError(
                        "pytest regression manifest exceeded its artifact bound"
                    )
                suite_id = "sha256:" + hashlib.sha256(manifest_json.encode()).hexdigest()
                manifest_artifact, manifest_hash = text_artifact(
                    runner.evidence,
                    f"pytest/{uuid4().hex}.regression-manifest.json",
                    manifest_json + "\n",
                    originating_tool="pytest",
                )
                nodeids_sha = hashlib.sha256("\n".join(pre.nodeids).encode()).hexdigest()

                execution_cmd = [
                    python,
                    "-m",
                    "pytest",
                    *common,
                    "--verbosity=2",
                    "-ra",
                    ".",
                ]
                preflight, run_raw = _run_phase(
                    runner,
                    sandbox,
                    execution_cmd,
                    env=env,
                    started=started,
                )
                execution_match = False
                post_match = False
                post_raw: BoundedSubprocessResult | None = None
                if not run_raw.timed_out and run_raw.returncode == 0:
                    execution_nodes = _parse_execution_nodes(
                        run_raw.stdout,
                        truncated=run_raw.stdout_truncated,
                    )
                    execution_match = execution_nodes == pre.nodeids
                    if execution_match:
                        preflight, post_raw = _run_phase(
                            runner,
                            sandbox,
                            collect_cmd,
                            env=env,
                            started=started,
                        )
                        if not post_raw.timed_out and post_raw.returncode == 0:
                            post = _parse_collection(
                                post_raw.stdout,
                                truncated=post_raw.stdout_truncated,
                            )
                            post_match = post == pre

                after = RepositoryInspector(runner.workspace).snapshot()
                workspace_reason = runner._workspace_integrity_failure(before, after)
                verified = (
                    run_raw.returncode == 0
                    and not run_raw.timed_out
                    and not run_raw.stderr_truncated
                    and execution_match
                    and post_match
                    and workspace_reason is None
                )
                exit_code = 124 if run_raw.timed_out else run_raw.returncode
                stderr = run_raw.stderr
                if run_raw.timed_out:
                    stderr += (
                        "\npytest regression execution exceeded its shared execution budget"
                    )
                if exit_code == 0 and not verified:
                    exit_code = 125
                    stderr += (
                        "\nregression-suite-integrity: collection/execution did not reconcile"
                    )
                if workspace_reason is not None:
                    stderr += f"\nworkspace-integrity: {workspace_reason}"

                suite = RegressionSuiteIdentity(
                    suite_id=suite_id,
                    git_sha=subject.git_sha,
                    source_fingerprint=subject.source_fingerprint,
                    execution_subject_digest=subject.digest,
                    pytest_version=pytest_version,
                    node_count=len(pre.nodeids),
                    nodeids_sha256=nodeids_sha,
                    config_path=config.path,
                    config_sha256=config.sha256,
                    config_options=config.options,
                    conftest_count=conftest_count,
                    conftest_sha256=conftest_sha,
                    manifest_artifact=manifest_artifact,
                    pre_post_collection_match=post_match,
                    execution_nodes_match=execution_match,
                )
                safe_stdout = redact_text(run_raw.stdout)
                safe_stderr = redact_text(stderr)
                log_artifact, log_hash = text_artifact(
                    runner.evidence,
                    f"pytest/{uuid4().hex}.log",
                    (
                        f"$ {' '.join(logical)}\n\n"
                        f"PRE-COLLECTION\n{redact_text(pre_raw.stdout)}\n\n"
                        f"EXECUTION\n{safe_stdout}\n\n"
                        f"STDERR\n{safe_stderr}\n\n"
                        "POST-COLLECTION\n"
                        + (
                            redact_text(post_raw.stdout)
                            if post_raw is not None
                            else "NOT_EXECUTED"
                        )
                        + "\n"
                    ),
                    originating_tool="pytest",
                )
                item = runner.evidence.add(
                    EvidenceItem(
                        run_id=runner.evidence.run_id,
                        kind=EvidenceKind.EXIT_CODE,
                        nature=EvidenceNature.OBSERVED_FACT,
                        source="pytest_regression_authority",
                        source_identifier=suite_id,
                        summary=(
                            "pytest full-regression suite passed with exact reconciliation"
                            if verified
                            else "pytest full-regression suite did not establish exact reconciliation"
                        ),
                        structured_data={
                            "exit_code": exit_code,
                            "pytest_returncode": run_raw.returncode,
                            "execution_started": True,
                            "workspace_integrity_verified": workspace_reason is None,
                            "workspace_integrity_reason": workspace_reason,
                            "regression_suite": suite.details(),
                            "sandbox": preflight.details(),
                            "manifest_content_hash": manifest_hash,
                        },
                        artifact_reference=log_artifact,
                        content_hash=log_hash,
                    )
                )
                return (
                    TestExecutionResult(
                        command=tuple(logical),
                        exit_code=exit_code,
                        stdout=safe_stdout,
                        stderr=safe_stderr,
                        duration_seconds=time.monotonic() - started,
                        evidence_ids=(item.id,),
                        execution_started=True,
                        block_reason=None,
                    ),
                    suite,
                )
    except (ExecutionSubjectError, RegressionSuiteError) as exc:
        return _blocked(runner, logical, started, str(exc)), None
    except (OSError, RuntimeError, ValueError) as exc:
        return (
            _blocked(
                runner,
                logical,
                started,
                f"pytest regression authority became unavailable: {type(exc).__name__}",
            ),
            None,
        )
