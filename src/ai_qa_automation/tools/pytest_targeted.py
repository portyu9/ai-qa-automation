from __future__ import annotations

import hashlib
import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4

from ..io_safety import parse_json_object_strict
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

_REPORT_PREFIX = "AIQA_TARGETED_OUTCOME_V1:"
_MAX_REPORT_BYTES = 8_192
_MAX_PASSED_PATHS = 4
_MAX_PATH_BYTES = 512
_MAX_CALL_REPORTS = 10_000


class TargetedExecutionError(RuntimeError):
    """Raised when controller-owned targeted outcome evidence is malformed."""


@dataclass(frozen=True, slots=True)
class TargetedExecutionIdentity:
    """Bounded controller-owned summary of pytest call-phase outcomes."""

    execution_id: str
    git_sha: str
    source_fingerprint: str
    execution_subject_digest: str
    report_complete: bool
    child_exit_code: int | None
    pytest_returncode: int | None
    call_report_count: int
    passed_call_count: int
    skipped_call_count: int
    xfail_call_count: int
    failed_call_count: int
    passed_paths: tuple[str, ...]
    report_sha256: str | None

    def details(self) -> dict[str, object]:
        return {
            "execution_id": self.execution_id,
            "git_sha": self.git_sha,
            "source_fingerprint": self.source_fingerprint,
            "execution_subject_digest": self.execution_subject_digest,
            "report_complete": self.report_complete,
            "child_exit_code": self.child_exit_code,
            "pytest_returncode": self.pytest_returncode,
            "call_report_count": self.call_report_count,
            "passed_call_count": self.passed_call_count,
            "skipped_call_count": self.skipped_call_count,
            "xfail_call_count": self.xfail_call_count,
            "failed_call_count": self.failed_call_count,
            "passed_paths": list(self.passed_paths),
            "report_sha256": self.report_sha256,
        }


_TARGETED_WRAPPER_SCRIPT = rf"""
import hashlib
import json
import os
import sys

PREFIX = {_REPORT_PREFIX!r}
MAX_REPORT_BYTES = {_MAX_REPORT_BYTES}
MAX_PASSED_PATHS = {_MAX_PASSED_PATHS}
MAX_PATH_BYTES = {_MAX_PATH_BYTES}
MAX_CALL_REPORTS = {_MAX_CALL_REPORTS}

read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_fd)
    try:
        import pytest

        class OutcomePlugin:
            def __init__(self):
                self.session_finished = False
                self.overflow = False
                self.call_report_count = 0
                self.passed_call_count = 0
                self.skipped_call_count = 0
                self.xfail_call_count = 0
                self.failed_call_count = 0
                self.passed_paths = []
                self._passed_path_set = set()

            def pytest_runtest_logreport(self, report):
                if getattr(report, "when", None) != "call":
                    return
                self.call_report_count += 1
                if self.call_report_count > MAX_CALL_REPORTS:
                    self.overflow = True
                    return
                outcome = str(getattr(report, "outcome", ""))
                wasxfail = getattr(report, "wasxfail", None) is not None
                if wasxfail:
                    self.xfail_call_count += 1
                    return
                if outcome == "passed":
                    self.passed_call_count += 1
                    nodeid = str(getattr(report, "nodeid", ""))
                    path = nodeid.split("::", 1)[0].replace("\\", "/")
                    encoded = path.encode("utf-8", "strict")
                    parts = path.split("/")
                    if (
                        not path
                        or path.startswith("/")
                        or any(part in ("", ".", "..") for part in parts)
                        or b"\x00" in encoded
                        or len(encoded) > MAX_PATH_BYTES
                    ):
                        self.overflow = True
                        return
                    if path not in self._passed_path_set:
                        if len(self.passed_paths) >= MAX_PASSED_PATHS:
                            self.overflow = True
                            return
                        self._passed_path_set.add(path)
                        self.passed_paths.append(path)
                    return
                if outcome == "skipped":
                    self.skipped_call_count += 1
                elif outcome == "failed":
                    self.failed_call_count += 1
                else:
                    self.overflow = True

            def pytest_sessionfinish(self, session, exitstatus):
                self.session_finished = True

        plugin = OutcomePlugin()
        returncode = int(pytest.main(sys.argv[1:], plugins=[plugin]))
        payload = {{
            "schema_version": 1,
            "pytest_returncode": returncode,
            "session_finished": plugin.session_finished,
            "overflow": plugin.overflow,
            "call_report_count": plugin.call_report_count,
            "passed_call_count": plugin.passed_call_count,
            "skipped_call_count": plugin.skipped_call_count,
            "xfail_call_count": plugin.xfail_call_count,
            "failed_call_count": plugin.failed_call_count,
            "passed_paths": plugin.passed_paths,
        }}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_REPORT_BYTES:
            encoded = json.dumps(
                {{
                    "schema_version": 1,
                    "pytest_returncode": returncode,
                    "session_finished": plugin.session_finished,
                    "overflow": True,
                    "call_report_count": plugin.call_report_count,
                    "passed_call_count": 0,
                    "skipped_call_count": 0,
                    "xfail_call_count": 0,
                    "failed_call_count": 0,
                    "passed_paths": [],
                }},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        view = memoryview(encoded)
        while view:
            written = os.write(write_fd, view)
            view = view[written:]
        os.close(write_fd)
        os._exit(returncode if 0 <= returncode <= 255 else 3)
    except BaseException:
        try:
            os.close(write_fd)
        except OSError:
            pass
        os._exit(3)

os.close(write_fd)
_, status = os.waitpid(pid, 0)
child_exit_code = os.waitstatus_to_exitcode(status)
os.set_blocking(read_fd, False)
chunks = []
total = 0
while True:
    try:
        chunk = os.read(read_fd, MAX_REPORT_BYTES + 1 - total)
    except BlockingIOError:
        break
    if not chunk:
        break
    chunks.append(chunk)
    total += len(chunk)
    if total > MAX_REPORT_BYTES:
        break
os.close(read_fd)
report_bytes = b"".join(chunks)
report = None
report_sha256 = None
if 0 < len(report_bytes) <= MAX_REPORT_BYTES:
    try:
        parsed = json.loads(report_bytes.decode("utf-8"))
        if isinstance(parsed, dict):
            report = parsed
            report_sha256 = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
    except (UnicodeDecodeError, ValueError):
        report = None

summary = {{
    "schema_version": 1,
    "report_complete": False,
    "child_exit_code": child_exit_code,
    "pytest_returncode": None,
    "session_finished": False,
    "overflow": True,
    "call_report_count": 0,
    "passed_call_count": 0,
    "skipped_call_count": 0,
    "xfail_call_count": 0,
    "failed_call_count": 0,
    "passed_paths": [],
    "report_sha256": report_sha256,
}}
if report is not None:
    pytest_returncode = report.get("pytest_returncode")
    session_finished = report.get("session_finished") is True
    overflow = report.get("overflow") is True
    summary.update(
        {{
            "pytest_returncode": pytest_returncode,
            "session_finished": session_finished,
            "overflow": overflow,
            "call_report_count": report.get("call_report_count", 0),
            "passed_call_count": report.get("passed_call_count", 0),
            "skipped_call_count": report.get("skipped_call_count", 0),
            "xfail_call_count": report.get("xfail_call_count", 0),
            "failed_call_count": report.get("failed_call_count", 0),
            "passed_paths": report.get("passed_paths", []),
        }}
    )
    summary["report_complete"] = (
        report.get("schema_version") == 1
        and type(pytest_returncode) is int
        and pytest_returncode == child_exit_code
        and session_finished
        and not overflow
    )

sys.stdout.write("\n" + PREFIX + json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
sys.stdout.flush()
raise SystemExit(child_exit_code if 0 <= child_exit_code <= 255 else 3)
"""


def _is_sha256_identity(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        return False
    try:
        int(value[7:], 16)
    except ValueError:
        return False
    return True


def _subject_identity(details: dict[str, object]) -> tuple[str, str, str]:
    git_sha = details.get("git_sha")
    source_fingerprint = details.get("source_fingerprint")
    digest = details.get("digest")
    if not isinstance(git_sha, str) or not git_sha or len(git_sha) > 128:
        raise TargetedExecutionError("targeted pytest execution subject lacked Git identity")
    if (
        not isinstance(source_fingerprint, str)
        or not source_fingerprint
        or len(source_fingerprint) > 256
    ):
        raise TargetedExecutionError("targeted pytest execution subject lacked source fingerprint")
    if not isinstance(digest, str) or not _is_sha256_identity(digest):
        raise TargetedExecutionError("targeted pytest execution subject digest was malformed")
    return git_sha, source_fingerprint, digest


def _safe_report_path(value: object) -> str:
    if not isinstance(value, str):
        raise TargetedExecutionError("targeted pytest report contained a non-string passed path")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise TargetedExecutionError("targeted pytest report contained invalid Unicode") from exc
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or len(encoded) > _MAX_PATH_BYTES
        or "\x00" in normalized
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != normalized
    ):
        raise TargetedExecutionError("targeted pytest report contained an unsafe passed path")
    return normalized


def _bounded_count(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    if type(value) is not int or value < 0 or value > _MAX_CALL_REPORTS:
        raise TargetedExecutionError(f"targeted pytest report contained invalid {key}")
    return value


def _parse_targeted_summary(
    stdout: str,
    *,
    truncated: bool,
    subject_details: dict[str, object],
) -> tuple[TargetedExecutionIdentity | None, str | None]:
    if truncated:
        return None, "targeted pytest stdout exceeded its deterministic bound"
    lines = stdout.splitlines()
    matches = [line for line in lines if line.startswith(_REPORT_PREFIX)]
    nonempty = [line for line in lines if line.strip()]
    if len(matches) != 1 or not nonempty or matches[0] != nonempty[-1]:
        return None, "targeted pytest controller summary was missing, duplicated, or not terminal"
    raw = matches[0][len(_REPORT_PREFIX) :]
    if len(raw.encode("utf-8")) > _MAX_REPORT_BYTES:
        return None, "targeted pytest controller summary exceeded its deterministic bound"
    try:
        git_sha, source_fingerprint, subject_digest = _subject_identity(subject_details)
        payload = parse_json_object_strict(raw, label="targeted pytest controller summary")
        if payload.get("schema_version") != 1:
            raise TargetedExecutionError("targeted pytest report schema was unsupported")
        report_complete = payload.get("report_complete")
        if type(report_complete) is not bool:
            raise TargetedExecutionError("targeted pytest report completeness was malformed")
        child_exit = payload.get("child_exit_code")
        pytest_returncode = payload.get("pytest_returncode")
        if type(child_exit) is not int:
            raise TargetedExecutionError("targeted pytest child exit code was malformed")
        if pytest_returncode is not None and type(pytest_returncode) is not int:
            raise TargetedExecutionError("targeted pytest return code was malformed")
        call_count = _bounded_count(payload, "call_report_count")
        passed_count = _bounded_count(payload, "passed_call_count")
        skipped_count = _bounded_count(payload, "skipped_call_count")
        xfail_count = _bounded_count(payload, "xfail_call_count")
        failed_count = _bounded_count(payload, "failed_call_count")
        if passed_count + skipped_count + xfail_count + failed_count > call_count:
            raise TargetedExecutionError("targeted pytest outcome counts were inconsistent")
        raw_paths = payload.get("passed_paths")
        if not isinstance(raw_paths, list) or len(raw_paths) > _MAX_PASSED_PATHS:
            raise TargetedExecutionError("targeted pytest passed-path set exceeded its bound")
        passed_paths = tuple(_safe_report_path(item) for item in raw_paths)
        if len(set(passed_paths)) != len(passed_paths):
            raise TargetedExecutionError("targeted pytest report duplicated a passed path")
        if passed_count < len(passed_paths):
            raise TargetedExecutionError("targeted pytest passed-path count was inconsistent")
        report_sha = payload.get("report_sha256")
        if report_sha is not None and not _is_sha256_identity(report_sha):
            raise TargetedExecutionError("targeted pytest report digest was malformed")
        if report_complete:
            if payload.get("session_finished") is not True or payload.get("overflow") is not False:
                raise TargetedExecutionError(
                    "targeted pytest complete report lacked terminal proof"
                )
            if pytest_returncode != child_exit:
                raise TargetedExecutionError("targeted pytest child/report exit codes disagreed")
            if report_sha is None:
                raise TargetedExecutionError("targeted pytest complete report lacked a digest")
    except (TargetedExecutionError, ValueError, UnicodeError) as exc:
        return None, str(exc)

    canonical = json.dumps(
        {
            "execution_subject": {
                "git_sha": git_sha,
                "source_fingerprint": source_fingerprint,
                "digest": subject_digest,
            },
            "report": payload,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    execution_id = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return (
        TargetedExecutionIdentity(
            execution_id=execution_id,
            git_sha=git_sha,
            source_fingerprint=source_fingerprint,
            execution_subject_digest=subject_digest,
            report_complete=report_complete,
            child_exit_code=child_exit,
            pytest_returncode=pytest_returncode,
            call_report_count=call_count,
            passed_call_count=passed_count,
            skipped_call_count=skipped_count,
            xfail_call_count=xfail_count,
            failed_call_count=failed_count,
            passed_paths=passed_paths,
            report_sha256=report_sha,
        ),
        None,
    )


def _without_controller_summary(stdout: str) -> str:
    lines = stdout.splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(_REPORT_PREFIX)]
    nonempty = [index for index, line in enumerate(lines) if line.strip()]
    if len(matches) == 1 and nonempty and matches[0] == nonempty[-1]:
        del lines[matches[0]]
    return "\n".join(lines)


def _blocked(
    runner: TestRunner,
    logical: list[str],
    started: float,
    reason: str,
) -> tuple[TestExecutionResult, None]:
    safe = redact_text(reason)
    artifact, digest = text_artifact(
        runner.evidence,
        f"pytest/{uuid4().hex}.log",
        f"$ {' '.join(logical)}\n\nTARGETED-EXECUTION-AUTHORITY\n{safe}\n",
        originating_tool="pytest",
    )
    item = runner.evidence.add(
        EvidenceItem(
            run_id=runner.evidence.run_id,
            kind=EvidenceKind.EXCEPTION,
            nature=EvidenceNature.OBSERVED_FACT,
            source="pytest_targeted_authority",
            summary="pytest targeted outcome authority was blocked before target execution",
            structured_data={"reason": safe, "execution_started": False},
            artifact_reference=artifact,
            content_hash=digest,
        )
    )
    return (
        TestExecutionResult(
            command=tuple(logical),
            exit_code=126,
            stdout="",
            stderr=safe,
            duration_seconds=time.monotonic() - started,
            evidence_ids=(item.id,),
            execution_started=False,
            block_reason=safe,
        ),
        None,
    )


def _record_execution(
    runner: TestRunner,
    *,
    logical: list[str],
    started: float,
    raw: BoundedSubprocessResult,
    preflight: PytestSandboxPreflight,
    before: object,
    execution_subject_details: dict[str, object],
    sandbox_postflight_reason: str | None,
) -> tuple[TestExecutionResult, TargetedExecutionIdentity | None]:
    after = RepositoryInspector(runner.workspace).snapshot()
    workspace_reason = runner._workspace_integrity_failure(before, after)
    identity, report_reason = _parse_targeted_summary(
        raw.stdout,
        truncated=raw.stdout_truncated,
        subject_details=execution_subject_details,
    )
    exit_code = 124 if raw.timed_out else raw.returncode
    reasons = [item for item in (sandbox_postflight_reason, workspace_reason) if item is not None]
    if exit_code == 0 and reasons:
        exit_code = 125
    stdout = redact_text(_without_controller_summary(raw.stdout))
    stderr = redact_text(raw.stderr)
    if raw.timed_out:
        stderr += f"\npytest exceeded {runner.timeout_seconds}s execution budget"
    if report_reason:
        stderr += f"\ntargeted-execution-evidence: {redact_text(report_reason)}"
    if reasons:
        stderr += "\ntargeted-execution-integrity: " + "; ".join(
            redact_text(item) for item in reasons
        )

    report_verified = (
        identity is not None
        and identity.report_complete
        and not raw.timed_out
        and raw.returncode == 0
        and exit_code == 0
        and sandbox_postflight_reason is None
        and workspace_reason is None
    )
    details = identity.details() if identity is not None else None
    artifact, digest = text_artifact(
        runner.evidence,
        f"pytest/{uuid4().hex}.log",
        (
            f"$ {' '.join(logical)}\n\n"
            f"STDOUT\n{stdout}\n\n"
            f"STDERR\n{stderr}\n\n"
            "TARGETED-EXECUTION-AUTHORITY\n"
            + json.dumps(
                {
                    "report_verified": report_verified,
                    "report_reason": report_reason,
                    "identity": details,
                },
                sort_keys=True,
                separators=(",", ":"),
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
            source="pytest_targeted_authority",
            source_identifier=(identity.execution_id if identity is not None else "unverified"),
            summary=(
                "pytest targeted execution produced controller-bound call-outcome evidence"
                if report_verified
                else "pytest targeted execution did not establish controller-bound call-outcome evidence"
            ),
            structured_data={
                "exit_code": exit_code,
                "pytest_returncode": raw.returncode,
                "timeout": raw.timed_out,
                "stdout_truncated": raw.stdout_truncated,
                "stderr_truncated": raw.stderr_truncated,
                "workspace_integrity_verified": workspace_reason is None,
                "workspace_integrity_reason": workspace_reason,
                "execution_subject": execution_subject_details,
                "targeted_outcome_report_verified": report_verified,
                "targeted_execution": details,
                "targeted_report_reason": report_reason,
                "sandbox": preflight.details(),
            },
            artifact_reference=artifact,
            content_hash=digest,
        )
    )
    return (
        TestExecutionResult(
            command=tuple(logical),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            evidence_ids=(item.id,),
            execution_started=True,
            block_reason=None,
        ),
        identity,
    )


def run_targeted_pytest(
    runner: TestRunner,
    requested_args: list[str],
) -> tuple[TestExecutionResult, TargetedExecutionIdentity | None]:
    """Run targeted pytest with bounded call-phase outcome evidence for mutation closure."""

    safe_args = runner._validate_pytest_args(requested_args)
    logical = ["python", "-m", "pytest", *safe_args]
    started = time.monotonic()
    before = RepositoryInspector(runner.workspace).snapshot()
    integrity = runner._workspace_integrity_failure(before, before)
    if integrity is not None:
        return _blocked(runner, logical, started, integrity)

    try:
        scratch, scratch_identity = runner._trusted_scratch_root()
        with materialized_pytest_execution_subject(
            runner.workspace,
            expected_snapshot=before,
            scratch_root=scratch,
            expected_scratch_root_identity=scratch_identity,
        ) as subject:
            execution_subject_details = subject.details()
            sandbox = runner._sandbox_for_materialized_workspace(subject.root)
            with tempfile.TemporaryDirectory(prefix="aiqa-pytest-home-", dir=scratch) as home:
                env = restricted_subprocess_env(
                    home=Path(home),
                    extra={
                        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                        "PYTHONDONTWRITEBYTECODE": "1",
                    },
                )
                command = [
                    str(sandbox.python_executable),
                    "-I",
                    "-c",
                    _TARGETED_WRAPPER_SCRIPT,
                    *safe_args,
                ]
                try:
                    preflight, raw = sandbox.run(
                        command,
                        env=env,
                        timeout_seconds=runner.timeout_seconds,
                    )
                except PytestSandboxUnavailable as exc:
                    return _blocked(
                        runner,
                        logical,
                        started,
                        exc.preflight.reason or "pytest sandbox is unavailable",
                    )
                except PytestSandboxExecutionUnverified as exc:
                    return _record_execution(
                        runner,
                        logical=logical,
                        started=started,
                        raw=exc.result,
                        preflight=exc.preflight,
                        before=before,
                        execution_subject_details=execution_subject_details,
                        sandbox_postflight_reason=exc.reason,
                    )
                return _record_execution(
                    runner,
                    logical=logical,
                    started=started,
                    raw=raw,
                    preflight=preflight,
                    before=before,
                    execution_subject_details=execution_subject_details,
                    sandbox_postflight_reason=None,
                )
    except (ExecutionSubjectError, OSError, RuntimeError, ValueError) as exc:
        return _blocked(
            runner,
            logical,
            started,
            f"pytest targeted execution authority became unavailable: {type(exc).__name__}",
        )
