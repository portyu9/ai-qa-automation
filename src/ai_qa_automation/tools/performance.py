from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from ..io_safety import read_text_bounded
from ..models import PerformanceMetrics, ToolDecision
from ..policy import PolicyEngine
from .execution_env import restricted_subprocess_env, run_bounded_subprocess

_URL_LITERAL = re.compile(r"https?://[^'\"`\s)]+", re.I)
_IMPORT_SPECIFIER = re.compile(r"(?:from\s+|import\s*\(\s*|import\s+)([\'\"])([^\'\"]+)\1")
_MAX_K6_MODULE_BYTES = 1_000_000
_MAX_K6_MODULES = 64
_MAX_K6_SUMMARY_BYTES = 1_000_000


class K6Runner:
    """Runs a target-bound k6 script only behind an infrastructure-egress prerequisite."""

    def __init__(
        self,
        workspace: Path,
        policy: PolicyEngine,
        timeout_seconds: int = 180,
        *,
        external_egress_enforced: bool = False,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("k6 timeout_seconds must be an integer")
        if timeout_seconds < 1:
            raise ValueError("k6 timeout_seconds must be positive")
        if not isinstance(external_egress_enforced, bool):
            raise ValueError("external_egress_enforced must be a boolean")
        self.workspace = workspace.resolve()
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.external_egress_enforced = external_egress_enforced

    def _validate_script(self, script: Path, target_url: str) -> Path:
        resolved = (script if script.is_absolute() else self.workspace / script).resolve()
        if (
            self.workspace not in resolved.parents
            or resolved.suffix != ".js"
            or not resolved.is_file()
        ):
            raise PermissionError(
                "k6 script must be an existing .js file inside the target workspace"
            )
        target_host = (urlparse(target_url).hostname or "").lower()
        if not target_host:
            raise PermissionError("k6 target URL must contain an explicit host")
        allowed_literal_hosts = {target_host}
        visited: set[Path] = set()
        root_uses_injected_target = False

        def inspect_module(module_path: Path, *, root: bool = False) -> None:
            nonlocal root_uses_injected_target
            module_path = module_path.resolve()
            if module_path in visited:
                return
            if (
                self.workspace not in module_path.parents
                or module_path.suffix != ".js"
                or not module_path.is_file()
            ):
                raise PermissionError(
                    "k6 local imports must resolve to .js files inside the target workspace"
                )
            if len(visited) >= _MAX_K6_MODULES:
                raise PermissionError(f"k6 import graph exceeds {_MAX_K6_MODULES} local modules")
            visited.add(module_path)
            try:
                source = read_text_bounded(
                    module_path,
                    max_bytes=_MAX_K6_MODULE_BYTES,
                    label="k6 module",
                )
            except ValueError as exc:
                raise PermissionError(
                    f"k6 module exceeds {_MAX_K6_MODULE_BYTES} byte limit"
                ) from exc
            except (OSError, UnicodeError) as exc:
                raise PermissionError("k6 module is unreadable") from exc
            if re.search(r"\bopen\s*\(", source):
                raise PermissionError("k6 scripts may not read local files through open()")
            if root and ("__ENV.BASE_URL" in source or "__ENV.TARGET_URL" in source):
                root_uses_injected_target = True
            for literal in _URL_LITERAL.findall(source):
                host = (urlparse(literal).hostname or "").lower()
                if host and host not in allowed_literal_hosts:
                    raise PermissionError(
                        f"k6 script contains an unapproved literal network host: {host}"
                    )
            for _quote, specifier in _IMPORT_SPECIFIER.findall(source):
                if specifier.startswith(("http://", "https://")):
                    raise PermissionError("remote k6 module imports are not allowed")
                if specifier.startswith("."):
                    imported = (module_path.parent / specifier).resolve()
                    if imported.suffix == "":
                        imported = imported.with_suffix(".js")
                    inspect_module(imported)
                elif specifier.startswith("k6/x/"):
                    raise PermissionError(
                        "k6 extension modules are not allowed in the controlled runner"
                    )
                elif specifier != "k6" and specifier not in {
                    "k6/http",
                    "k6/metrics",
                    "k6/execution",
                    "k6/encoding",
                    "k6/crypto",
                    "k6/data",
                    "k6/html",
                    "k6/timers",
                }:
                    raise PermissionError(f"unapproved k6 module import: {specifier}")

        inspect_module(resolved, root=True)
        if not root_uses_injected_target:
            raise PermissionError("k6 script must consume an injected BASE_URL or TARGET_URL")
        return resolved

    @staticmethod
    def _metric_values(data: dict[str, Any], metric: str) -> dict[str, Any]:
        metrics = data.get("metrics")
        if not isinstance(metrics, dict):
            raise RuntimeError("k6 summary is missing the metrics object")
        raw_metric = metrics.get(metric)
        if not isinstance(raw_metric, dict):
            raise RuntimeError(f"k6 summary is missing required metric: {metric}")
        values = raw_metric.get("values")
        if not isinstance(values, dict):
            raise RuntimeError(f"k6 metric lacks a values object: {metric}")
        return values

    @staticmethod
    def _required_number(values: dict[str, Any], key: str, *, metric: str) -> float:
        if key not in values:
            raise RuntimeError(f"k6 metric {metric} is missing required value: {key}")
        raw = values[key]
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise RuntimeError(f"k6 metric {metric}.{key} is not numeric")
        return float(raw)

    @classmethod
    def _parse_metrics(cls, data: dict[str, Any]) -> PerformanceMetrics:
        duration = cls._metric_values(data, "http_req_duration")
        requests = cls._metric_values(data, "http_reqs")
        failures = cls._metric_values(data, "http_req_failed")
        if "p(99)" in duration:
            p99 = cls._required_number(duration, "p(99)", metric="http_req_duration")
        elif "max" in duration:
            p99 = cls._required_number(duration, "max", metric="http_req_duration")
        else:
            raise RuntimeError("k6 metric http_req_duration is missing p(99) and max")
        return PerformanceMetrics(
            p50_ms=cls._required_number(duration, "med", metric="http_req_duration"),
            p90_ms=cls._required_number(duration, "p(90)", metric="http_req_duration"),
            p95_ms=cls._required_number(duration, "p(95)", metric="http_req_duration"),
            p99_ms=p99,
            request_rate=cls._required_number(requests, "rate", metric="http_reqs"),
            error_rate=cls._required_number(failures, "rate", metric="http_req_failed"),
        )

    def run(self, script: Path, *, target_url: str, environment: str) -> PerformanceMetrics:
        if not self.external_egress_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level egress enforcement; "
                "static JavaScript inspection is not a network sandbox"
            )
        decision = self.policy.authorize_performance_target(target_url, environment=environment)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(decision.reason)
        script_path = self._validate_script(script, target_url)
        if shutil.which("k6") is None:
            raise RuntimeError("k6 is not installed; runtime validation is NOT_VERIFIED")

        data: dict[str, Any]
        with tempfile.TemporaryDirectory(prefix="aiqa-k6-runtime-") as temp_runtime:
            runtime_root = Path(temp_runtime)
            summary_path = runtime_root / f"summary-{uuid4().hex}.json"
            command = [
                "k6",
                "run",
                "-e",
                f"BASE_URL={target_url.rstrip('/')}",
                "-e",
                f"TARGET_URL={target_url.rstrip('/')}",
                "--summary-export",
                str(summary_path),
                str(script_path),
            ]
            env = restricted_subprocess_env(
                home=runtime_root,
                extra={
                    "BASE_URL": target_url.rstrip("/"),
                    "TARGET_URL": target_url.rstrip("/"),
                    "K6_NO_USAGE_REPORT": "true",
                },
            )
            result = run_bounded_subprocess(
                command,
                cwd=self.workspace,
                env=env,
                timeout_seconds=self.timeout_seconds,
            )
            if result.timed_out:
                raise RuntimeError(f"k6 exceeded {self.timeout_seconds}s execution budget")
            if result.returncode != 0:
                raise RuntimeError(result.stderr[-3000:] or "k6 failed")
            if not summary_path.is_file():
                raise RuntimeError("k6 completed without producing the required summary artifact")
            try:
                rendered = read_text_bounded(
                    summary_path,
                    max_bytes=_MAX_K6_SUMMARY_BYTES,
                    label="k6 summary",
                )
            except ValueError as exc:
                raise RuntimeError(
                    f"k6 summary exceeds {_MAX_K6_SUMMARY_BYTES} byte ingestion limit"
                ) from exc
            data = json.loads(rendered)
            if not isinstance(data, dict):
                raise RuntimeError("k6 summary root must be a JSON object")

        return self._parse_metrics(data)
