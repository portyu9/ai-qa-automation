from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from ..evidence import EvidenceStore
from ..models import EvidenceItem, EvidenceKind, EvidenceNature


@dataclass(frozen=True)
class TestExecutionResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    evidence_ids: tuple[str, ...]


class TestRunner:
    """Runs test frameworks through an explicit executable allowlist."""

    _ALLOWED_EXECUTABLES = {"pytest", "python", "python3"}

    def __init__(self, workspace: Path, evidence: EvidenceStore, timeout_seconds: int = 120) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.evidence = evidence
        self.timeout_seconds = timeout_seconds

    def run_pytest(self, args: list[str] | None = None) -> TestExecutionResult:
        command = ["python", "-m", "pytest", *(args or [])]
        return self.run(command)

    def run(self, command: list[str]) -> TestExecutionResult:
        if not command or Path(command[0]).name not in self._ALLOWED_EXECUTABLES:
            raise PermissionError("test runner executable is not allowlisted")
        if command[:3] not in (["python", "-m", "pytest"], ["python3", "-m", "pytest"]) and command[0] != "pytest":
            raise PermissionError("only pytest execution is supported by this narrow tool")

        start = time.monotonic()
        env = {k: v for k, v in os.environ.items() if k not in {"ANTHROPIC_API_KEY", "GITHUB_PERSONAL_ACCESS_TOKEN"}}
        result = subprocess.run(
            command,
            cwd=self.workspace,
            text=True,
            capture_output=True,
            timeout=self.timeout_seconds,
            check=False,
            env=env,
        )
        duration = time.monotonic() - start
        exit_item = self.evidence.add(
            EvidenceItem(
                run_id=self.evidence.run_id,
                kind=EvidenceKind.EXIT_CODE,
                nature=EvidenceNature.OBSERVED_FACT,
                source="pytest",
                source_identifier=" ".join(command),
                summary=f"pytest exited with code {result.returncode}",
                structured_data={"exit_code": result.returncode, "duration_seconds": duration},
            )
        )
        if result.returncode != 0:
            exception = self.evidence.add(
                EvidenceItem(
                    run_id=self.evidence.run_id,
                    kind=EvidenceKind.EXCEPTION,
                    source="pytest",
                    summary="pytest execution failed",
                    structured_data={"stderr": result.stderr[-4000:], "stdout": result.stdout[-4000:]},
                )
            )
            ids = (exit_item.id, exception.id)
        else:
            ids = (exit_item.id,)
        return TestExecutionResult(
            command=tuple(command),
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_seconds=duration,
            evidence_ids=ids,
        )
