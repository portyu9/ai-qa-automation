from __future__ import annotations

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind, EvidenceNature
from ..redaction import redact_text
from .artifacts import text_artifact
from .execution_env import restricted_subprocess_env


@dataclass(frozen=True)
class TestExecutionResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    evidence_ids: tuple[str, ...]


class TestRunner:
    """Runs pytest through a bounded argument surface inside one target workspace."""

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

    def __init__(self, workspace: Path, evidence: EvidenceStore, timeout_seconds: int = 120) -> None:
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

        start = time.monotonic()
        timed_out = False
        with tempfile.TemporaryDirectory(prefix="aiqa-pytest-home-") as temp_home:
            env = restricted_subprocess_env(
                home=Path(temp_home),
                extra={"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
            )
            try:
                result = subprocess.run(
                    command,
                    cwd=self.workspace,
                    text=True,
                    capture_output=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    env=env,
                )
                exit_code = result.returncode
                raw_stdout = result.stdout
                raw_stderr = result.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                exit_code = 124
                raw_stdout = exc.stdout or ""
                raw_stderr = exc.stderr or ""
                if isinstance(raw_stdout, bytes):
                    raw_stdout = raw_stdout.decode("utf-8", errors="replace")
                if isinstance(raw_stderr, bytes):
                    raw_stderr = raw_stderr.decode("utf-8", errors="replace")
                raw_stderr += f"\npytest exceeded {self.timeout_seconds}s execution budget"
        duration = time.monotonic() - start
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
                    f"pytest exceeded {self.timeout_seconds}s execution budget"
                    if timed_out
                    else f"pytest exited with code {exit_code}"
                ),
                structured_data={
                    "exit_code": exit_code,
                    "duration_seconds": duration,
                    "timeout": timed_out,
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
                    summary="pytest execution timed out" if timed_out else "pytest execution failed",
                    structured_data={
                        "stderr": safe_stderr[-4000:],
                        "stdout": safe_stdout[-4000:],
                        "timeout": timed_out,
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
                raise PermissionError(f"pytest option is outside the approved argument surface: {arg}")
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
