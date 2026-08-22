from __future__ import annotations

import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind, EvidenceNature
from ..redaction import redact_text
from .artifacts import text_artifact
from .execution_env import restricted_subprocess_env, run_bounded_subprocess
from .repository import RepositoryInspector


@dataclass(frozen=True)
class TestExecutionResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    evidence_ids: tuple[str, ...]


class TestRunner:
    """Runs pytest through a bounded argument surface inside one target workspace.

    A zero pytest exit code is retained only when the Git-backed workspace is
    completely fingerprinted and unchanged across execution. Target tests are
    executable repository code; they therefore cannot be allowed to modify the
    repository and still certify their own result.
    """

    _SAFE_FLAGS = {
        "-q",
        "--quiet",
        "-x",
        "--exitfirst",
        "-s",
        "--disable-warnings",
        "--strict-markers",
    }
    _SAFE_VALUE_OPTIONS = {"-k", "-m", "--maxfail", "--tb"}
    _SAFE_VALUE_PREFIXES = ("--maxfail=", "--tb=")
    _WORKSPACE_INTEGRITY_EXIT_CODE = 125
    _TIMEOUT_EXIT_CODE = 124

    def __init__(
        self, workspace: Path, evidence: EvidenceStore, timeout_seconds: int = 120
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("pytest timeout_seconds must be an integer")
        if timeout_seconds < 1:
            raise ValueError("pytest timeout_seconds must be positive")
        self.workspace = workspace.expanduser().resolve()
        self.evidence = evidence
        self.timeout_seconds = timeout_seconds

    def run_pytest(self, args: list[str] | None = None) -> TestExecutionResult:
        safe_args = self._validate_pytest_args(args or [])
        return self.run(["python", "-m", "pytest", *safe_args])

    def run(self, command: list[str]) -> TestExecutionResult:
        if command[:3] not in (["python", "-m", "pytest"], ["python3", "-m", "pytest"]):
            if not command or command[0] != "pytest":
                raise PermissionError("only pytest execution is supported by this narrow tool")
            safe_args = self._validate_pytest_args(command[1:])
            command = ["pytest", *safe_args]
        else:
            safe_args = self._validate_pytest_args(command[3:])
            command = [*command[:3], *safe_args]

        before = RepositoryInspector(self.workspace).snapshot()
        start = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="aiqa-pytest-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={
                    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
            process_result = run_bounded_subprocess(
                command,
                cwd=self.workspace,
                env=env,
                timeout_seconds=self.timeout_seconds,
            )
        duration = time.monotonic() - start
        timed_out = process_result.timed_out
        exit_code = self._TIMEOUT_EXIT_CODE if timed_out else process_result.returncode
        raw_stdout = process_result.stdout
        raw_stderr = process_result.stderr
        if timed_out:
            raw_stderr += f"\npytest exceeded {self.timeout_seconds}s execution budget"

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
            f"$ {' '.join(command)}\n\nSTDOUT\n{safe_stdout}\n\nSTDERR\n{safe_stderr}\n",
            originating_tool="pytest",
        )
        exit_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.EXIT_CODE,
                nature=EvidenceNature.OBSERVED_FACT,
                source="pytest",
                source_identifier=" ".join(command),
                summary=(
                    f"pytest workspace-integrity gate failed: {integrity_reason}"
                    if integrity_reason and not timed_out
                    else (
                        f"pytest exceeded {self.timeout_seconds}s execution budget"
                        if timed_out
                        else f"pytest exited with code {exit_code}"
                    )
                ),
                structured_data={
                    "exit_code": exit_code,
                    "duration_seconds": duration,
                    "timeout": timed_out,
                    "stdout_truncated": process_result.stdout_truncated,
                    "stderr_truncated": process_result.stderr_truncated,
                    "workspace_integrity_verified": integrity_reason is None,
                    "workspace_integrity_reason": integrity_reason,
                    "workspace_fingerprint_before": before.fingerprint,
                    "workspace_fingerprint_after": after.fingerprint,
                },
                artifact_reference=artifact_path,
                content_hash=artifact_hash,
            )
        )
        if exit_code != 0:
            exception = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.EXCEPTION,
                    source="pytest",
                    summary=(
                        "pytest execution timed out"
                        if timed_out
                        else (
                            "pytest changed or could not completely fingerprint the target workspace"
                            if integrity_reason
                            else (
                                "pytest tests failed"
                                if exit_code == 1
                                else "pytest execution did not produce a valid test result"
                            )
                        )
                    ),
                    structured_data={
                        "exit_code": exit_code,
                        "stderr": safe_stderr[-4000:],
                        "stdout": safe_stdout[-4000:],
                        "timeout": timed_out,
                        "stdout_truncated": process_result.stdout_truncated,
                        "stderr_truncated": process_result.stderr_truncated,
                        "workspace_integrity_verified": integrity_reason is None,
                        "workspace_integrity_reason": integrity_reason,
                    },
                    artifact_reference=artifact_path,
                    content_hash=artifact_hash,
                )
            )
            ids = (exit_item.id, exception.id)
        else:
            ids = (exit_item.id,)
        return TestExecutionResult(
            command=tuple(command),
            exit_code=exit_code,
            stdout=safe_stdout,
            stderr=safe_stderr,
            duration_seconds=duration,
            evidence_ids=ids,
        )

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
