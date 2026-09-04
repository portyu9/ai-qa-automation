from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable
from uuid import uuid4

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind, EvidenceNature
from ..redaction import redact_text
from .artifacts import text_artifact
from .execution_env import restricted_subprocess_env
from .execution_subject import ExecutionSubjectError, materialized_pytest_execution_subject
from .pytest_sandbox import (
    BubblewrapPytestSandbox,
    PytestSandbox,
    PytestSandboxExecutionUnverified,
    PytestSandboxPreflight,
    PytestSandboxUnavailable,
)
from .repository import RepositoryInspector


@runtime_checkable
class MaterializedWorkspaceSandboxFactory(Protocol):
    """Trusted extension seam for sandboxes that bind an explicit frozen workspace."""

    def for_materialized_workspace(self, workspace: Path) -> PytestSandbox: ...


@dataclass(frozen=True)
class TestExecutionResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    evidence_ids: tuple[str, ...]
    execution_started: bool
    block_reason: str | None


class TestRunner:
    """Run target pytest only from a frozen subject inside a verified OS sandbox.

    The target repository is executable untrusted content. A zero pytest exit code
    is retained only when a complete Git-backed repository subject was materialized
    into a controller-owned bounded tree, a concrete Bubblewrap capability proof
    succeeded for that tree, the sandboxed target process completed, and the source
    workspace remained revision/fingerprint-stable through closure. Ordinary
    Git-ignored source bytes and Git metadata never enter the pytest namespace.
    There is no direct-host fallback.
    """

    _SAFE_FLAGS: ClassVar[set[str]] = {
        "-q",
        "--quiet",
        "-x",
        "--exitfirst",
        "-s",
        "--disable-warnings",
        "--strict-markers",
    }
    _SAFE_VALUE_OPTIONS: ClassVar[set[str]] = {"-k", "-m", "--maxfail", "--tb"}
    _SAFE_VALUE_PREFIXES = ("--maxfail=", "--tb=")
    _WORKSPACE_INTEGRITY_EXIT_CODE = 125
    _SANDBOX_BLOCKED_EXIT_CODE = 126
    _TIMEOUT_EXIT_CODE = 124

    def __init__(
        self,
        workspace: Path,
        evidence: EvidenceStore,
        timeout_seconds: int = 120,
        *,
        sandbox: PytestSandbox | None = None,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("pytest timeout_seconds must be an integer")
        if timeout_seconds < 1:
            raise ValueError("pytest timeout_seconds must be positive")
        self.workspace = workspace.expanduser().resolve()
        self.evidence = evidence
        self.timeout_seconds = timeout_seconds
        self.sandbox = sandbox or BubblewrapPytestSandbox(
            self.workspace,
            evidence_root=self.evidence.run_root,
        )

    def sandbox_preflight(self) -> PytestSandboxPreflight:
        """Execute the concrete isolation capability proof used by live admission."""
        return self.sandbox.preflight()

    def run_pytest(self, args: list[str] | None = None) -> TestExecutionResult:
        safe_args = self._validate_pytest_args(args or [])
        return self.run(["python", "-m", "pytest", *safe_args])

    def run(self, command: list[str]) -> TestExecutionResult:
        if command[:3] not in (["python", "-m", "pytest"], ["python3", "-m", "pytest"]):
            if not command or command[0] != "pytest":
                raise PermissionError("only pytest execution is supported by this narrow tool")
            safe_args = self._validate_pytest_args(command[1:])
        else:
            safe_args = self._validate_pytest_args(command[3:])
        logical_command = ["python", "-m", "pytest", *safe_args]

        before = RepositoryInspector(self.workspace).snapshot()
        start = time.monotonic()
        preflight: PytestSandboxPreflight
        process_result = None
        sandbox_postflight_reason: str | None = None
        execution_subject_details: dict[str, object] | None = None
        pre_execution_integrity_reason = self._workspace_integrity_failure(before, before)

        if pre_execution_integrity_reason is not None:
            preflight = PytestSandboxPreflight(
                ready=False,
                backend="bubblewrap",
                reason=(
                    "pytest execution subject could not be authorized before target execution: "
                    + pre_execution_integrity_reason
                ),
            )
        else:
            try:
                with materialized_pytest_execution_subject(
                    self.workspace,
                    expected_snapshot=before,
                ) as execution_subject:
                    execution_subject_details = execution_subject.details()
                    execution_sandbox = self._sandbox_for_materialized_workspace(
                        execution_subject.root
                    )
                    with tempfile.TemporaryDirectory(prefix="aiqa-pytest-home-") as temp_home:
                        env = restricted_subprocess_env(
                            home=Path(temp_home),
                            extra={
                                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                                "PYTHONDONTWRITEBYTECODE": "1",
                            },
                        )
                        try:
                            preflight, process_result = execution_sandbox.run(
                                [
                                    str(execution_sandbox.python_executable),
                                    "-m",
                                    "pytest",
                                    *safe_args,
                                ],
                                env=env,
                                timeout_seconds=self.timeout_seconds,
                            )
                        except PytestSandboxUnavailable as exc:
                            preflight = exc.preflight
                            process_result = None
                        except PytestSandboxExecutionUnverified as exc:
                            preflight = exc.preflight
                            process_result = exc.result
                            sandbox_postflight_reason = exc.reason
                        except (OSError, RuntimeError, ValueError) as exc:
                            preflight = PytestSandboxPreflight(
                                ready=False,
                                backend="bubblewrap",
                                reason=(
                                    "sandbox execution authority became unavailable: "
                                    f"{type(exc).__name__}"
                                ),
                            )
                            process_result = None
            except ExecutionSubjectError as exc:
                preflight = PytestSandboxPreflight(
                    ready=False,
                    backend="bubblewrap",
                    reason=f"pytest execution subject materialization failed: {exc}",
                )
                process_result = None
            except (OSError, RuntimeError, ValueError) as exc:
                preflight = PytestSandboxPreflight(
                    ready=False,
                    backend="bubblewrap",
                    reason=(
                        "pytest execution subject authority became unavailable: "
                        f"{type(exc).__name__}"
                    ),
                )
                process_result = None
        duration = time.monotonic() - start

        sandbox_blocked = process_result is None
        timed_out = False if process_result is None else process_result.timed_out
        if process_result is None:
            exit_code = self._SANDBOX_BLOCKED_EXIT_CODE
            raw_stdout = ""
            raw_stderr = preflight.reason or "pytest sandbox is unavailable"
            stdout_truncated = False
            stderr_truncated = False
        else:
            exit_code = self._TIMEOUT_EXIT_CODE if timed_out else process_result.returncode
            raw_stdout = process_result.stdout
            raw_stderr = process_result.stderr
            stdout_truncated = process_result.stdout_truncated
            stderr_truncated = process_result.stderr_truncated
            if timed_out:
                raw_stderr += f"\npytest exceeded {self.timeout_seconds}s execution budget"
            if sandbox_postflight_reason is not None:
                raw_stderr += f"\nsandbox-integrity: {sandbox_postflight_reason}"
                if exit_code == 0:
                    exit_code = self._WORKSPACE_INTEGRITY_EXIT_CODE

        after = RepositoryInspector(self.workspace).snapshot()
        integrity_reason = self._workspace_integrity_failure(before, after)
        if integrity_reason:
            raw_stderr += f"\nworkspace-integrity: {integrity_reason}"
            if exit_code == 0:
                exit_code = self._WORKSPACE_INTEGRITY_EXIT_CODE

        safe_stdout = redact_text(raw_stdout)
        safe_stderr = redact_text(raw_stderr)
        artifact_path, artifact_hash = text_artifact(
            self.evidence,
            f"pytest/{uuid4().hex}.log",
            f"$ {' '.join(logical_command)}\n\nSTDOUT\n{safe_stdout}\n\nSTDERR\n{safe_stderr}\n",
            originating_tool="pytest",
        )
        isolation_details = preflight.details()
        isolation_details["execution_started"] = not sandbox_blocked
        isolation_details["postflight_verified"] = (
            not sandbox_blocked and sandbox_postflight_reason is None
        )
        isolation_details["postflight_reason"] = sandbox_postflight_reason
        isolation_details["cpu_limit_seconds"] = (
            self.timeout_seconds + 1
            if not sandbox_blocked and preflight.backend == "bubblewrap"
            else None
        )
        isolation_details["execution_subject"] = execution_subject_details
        exit_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.EXIT_CODE,
                nature=EvidenceNature.OBSERVED_FACT,
                source="pytest",
                source_identifier=" ".join(logical_command),
                summary=(
                    f"pytest sandbox blocked execution: {preflight.reason}"
                    if sandbox_blocked
                    else (
                        f"pytest workspace-integrity gate failed: {integrity_reason}"
                        if integrity_reason and not timed_out
                        else (
                            f"pytest exceeded {self.timeout_seconds}s execution budget"
                            if timed_out
                            else f"pytest exited with code {exit_code}"
                        )
                    )
                ),
                structured_data={
                    "exit_code": exit_code,
                    "duration_seconds": duration,
                    "timeout": timed_out,
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                    "workspace_integrity_verified": integrity_reason is None,
                    "workspace_integrity_reason": integrity_reason,
                    "workspace_fingerprint_before": before.fingerprint,
                    "workspace_fingerprint_after": after.fingerprint,
                    "execution_subject": execution_subject_details,
                    "sandbox": isolation_details,
                },
                artifact_reference=artifact_path,
                content_hash=artifact_hash,
            )
        )
        ids: tuple[str, ...]
        if exit_code != 0:
            exception = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.EXCEPTION,
                    nature=EvidenceNature.OBSERVED_FACT,
                    source="pytest",
                    summary=(
                        "pytest sandbox blocked target-code execution"
                        if sandbox_blocked
                        else (
                            "pytest execution timed out"
                            if timed_out
                            else (
                                "pytest changed or could not completely fingerprint "
                                "the target workspace"
                                if integrity_reason
                                else (
                                    "pytest tests failed"
                                    if exit_code == 1
                                    else "pytest execution did not produce a valid test result"
                                )
                            )
                        )
                    ),
                    structured_data={
                        "exit_code": exit_code,
                        "stderr": safe_stderr[-4000:],
                        "stdout": safe_stdout[-4000:],
                        "timeout": timed_out,
                        "stdout_truncated": stdout_truncated,
                        "stderr_truncated": stderr_truncated,
                        "workspace_integrity_verified": integrity_reason is None,
                        "workspace_integrity_reason": integrity_reason,
                        "execution_subject": execution_subject_details,
                        "sandbox": isolation_details,
                    },
                    artifact_reference=artifact_path,
                    content_hash=artifact_hash,
                )
            )
            ids = (exit_item.id, exception.id)
        else:
            ids = (exit_item.id,)
        return TestExecutionResult(
            command=tuple(logical_command),
            exit_code=exit_code,
            stdout=safe_stdout,
            stderr=safe_stderr,
            duration_seconds=duration,
            evidence_ids=ids,
            execution_started=not sandbox_blocked,
            block_reason=(preflight.reason if sandbox_blocked else None),
        )

    def _sandbox_for_materialized_workspace(self, workspace: Path) -> PytestSandbox:
        if isinstance(self.sandbox, BubblewrapPytestSandbox):
            return BubblewrapPytestSandbox(
                workspace,
                evidence_root=self.evidence.run_root,
            )
        if isinstance(self.sandbox, MaterializedWorkspaceSandboxFactory):
            sandbox = self.sandbox.for_materialized_workspace(workspace)
            if sandbox is self.sandbox and Path(workspace).resolve() == self.workspace:
                raise ExecutionSubjectError(
                    "custom pytest sandbox did not switch to the materialized workspace"
                )
            return sandbox
        raise ExecutionSubjectError(
            "custom pytest sandbox must explicitly bind the materialized execution workspace"
        )

    def sandbox_python_executable(self) -> str:
        return str(self.sandbox.python_executable)

    @staticmethod
    def _workspace_integrity_failure(before: object, after: object) -> str | None:
        before_sha = getattr(before, "git_sha", None)
        after_sha = getattr(after, "git_sha", None)
        if not before_sha or not after_sha:
            return "pytest validation requires a Git-backed target workspace"
        before_complete = bool(getattr(before, "fingerprint_complete", False))
        after_complete = bool(getattr(after, "fingerprint_complete", False))
        if not before_complete or not after_complete:
            before_reasons = ",".join(
                str(item) for item in getattr(before, "fingerprint_incomplete_reasons", ())
            )
            after_reasons = ",".join(
                str(item) for item in getattr(after, "fingerprint_incomplete_reasons", ())
            )
            reasons = "; ".join(
                item
                for item in (
                    f"before={before_reasons}" if before_reasons else "",
                    f"after={after_reasons}" if after_reasons else "",
                )
                if item
            )
            return "workspace fingerprint is incomplete" + (f" ({reasons})" if reasons else "")
        if before_sha != after_sha:
            return "Git HEAD changed during pytest execution"
        if getattr(before, "fingerprint", None) != getattr(after, "fingerprint", None):
            return "target workspace changed during pytest execution"
        return None

    def _validate_pytest_args(self, args: list[str]) -> list[str]:
        safe: list[str] = []
        index = 0
        while index < len(args):
            arg = str(args[index])
            if arg in self._SAFE_FLAGS or arg.startswith(self._SAFE_VALUE_PREFIXES):
                safe.append(arg)
                index += 1
                continue
            if arg in self._SAFE_VALUE_OPTIONS:
                if index + 1 >= len(args):
                    raise PermissionError(f"pytest option requires a value: {arg}")
                value = str(args[index + 1])
                if value.startswith("-"):
                    raise PermissionError(f"invalid pytest option value for {arg}")
                safe.extend([arg, value])
                index += 2
                continue
            if arg.startswith("-"):
                raise PermissionError(
                    f"pytest option is outside the approved argument surface: {arg}"
                )
            self._validate_selector(arg)
            safe.append(arg)
            index += 1
        return safe

    def _validate_selector(self, selector: str) -> None:
        path_text = selector.split("::", 1)[0]
        if not path_text:
            raise PermissionError("empty pytest selector is not allowed")
        path = Path(path_text)
        if path.is_absolute() or ".." in path.parts:
            raise PermissionError("pytest selectors must stay inside the target workspace")
        resolved = (self.workspace / path).resolve()
        if resolved != self.workspace and self.workspace not in resolved.parents:
            raise PermissionError("pytest selector resolves outside the target workspace")