from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from ..fs_authority import pin_directory_identity, read_bytes_confined
from ..io_safety import read_json_object_bounded
from ..models import PerformanceMetrics, ToolDecision
from ..policy import PolicyEngine
from .execution_env import restricted_subprocess_env, run_bounded_subprocess

_URL_LITERAL = re.compile(r"https?://[^'\"`\s)]+", re.I)
_IMPORT_SPECIFIER = re.compile(r"(?:from\s+|import\s+)([\'\"])([^\'\"]+)\1")
_COMMONJS_REQUIRE = re.compile(r"\brequire\b")
_DYNAMIC_IMPORT = re.compile(r"\bimport\s*\(")
_MAX_K6_MODULE_BYTES = 1_000_000
_MAX_K6_MODULES = 64
_MAX_K6_SUMMARY_BYTES = 1_000_000
_K6_SNAPSHOT_HASH_DOMAIN = b"ai-qa-k6-module-snapshot-v1\0"


class K6ExecutionMetrics(PerformanceMetrics):
    """Observed k6 metrics bound to the exact validated module snapshot."""

    module_snapshot_sha256: str


class K6Runner:
    """Runs a target-bound k6 script only behind trusted execution isolation."""

    def __init__(
        self,
        workspace: Path,
        policy: PolicyEngine,
        timeout_seconds: int = 180,
        *,
        external_egress_enforced: bool = False,
        external_process_isolation_enforced: bool = False,
        external_module_isolation_enforced: bool = False,
        external_resource_limits_enforced: bool = False,
        external_workload_limits_enforced: bool = False,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("k6 timeout_seconds must be an integer")
        if timeout_seconds < 1:
            raise ValueError("k6 timeout_seconds must be positive")
        if not isinstance(external_egress_enforced, bool):
            raise ValueError("external_egress_enforced must be a boolean")
        if not isinstance(external_process_isolation_enforced, bool):
            raise ValueError("external_process_isolation_enforced must be a boolean")
        if not isinstance(external_module_isolation_enforced, bool):
            raise ValueError("external_module_isolation_enforced must be a boolean")
        if not isinstance(external_resource_limits_enforced, bool):
            raise ValueError("external_resource_limits_enforced must be a boolean")
        if not isinstance(external_workload_limits_enforced, bool):
            raise ValueError("external_workload_limits_enforced must be a boolean")
        self.workspace = workspace.expanduser().absolute()
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.external_egress_enforced = external_egress_enforced
        self.external_process_isolation_enforced = external_process_isolation_enforced
        self.external_module_isolation_enforced = external_module_isolation_enforced
        self.external_resource_limits_enforced = external_resource_limits_enforced
        self.external_workload_limits_enforced = external_workload_limits_enforced
        try:
            self._workspace_root_identity = pin_directory_identity(
                self.workspace,
                label="k6 workspace",
            )
        except (OSError, ValueError, RuntimeError):
            self._workspace_root_identity = None

    def _workspace_module_path(self, candidate: Path) -> Path:
        raw = candidate if candidate.is_absolute() else self.workspace / candidate
        lexical = Path(os.path.abspath(raw))
        try:
            relative_path = lexical.relative_to(self.workspace)
        except ValueError as exc:
            raise PermissionError(
                "k6 local imports must resolve to .js files inside the target workspace"
            ) from exc
        if not relative_path.parts or lexical.suffix != ".js":
            raise PermissionError(
                "k6 local imports must resolve to .js files inside the target workspace"
            )
        return lexical

    def _collect_validated_modules(
        self,
        script: Path,
        target_url: str,
    ) -> tuple[Path, dict[Path, str]]:
        if self._workspace_root_identity is None:
            raise PermissionError(
                "k6 module ingestion requires descriptor-relative no-follow filesystem authority "
                "for a stable target workspace"
            )
        try:
            resolved = self._workspace_module_path(script)
        except PermissionError as exc:
            raise PermissionError(
                "k6 script must be an existing .js file inside the target workspace"
            ) from exc
        target_host = (urlparse(target_url).hostname or "").lower()
        if not target_host:
            raise PermissionError("k6 target URL must contain an explicit host")
        allowed_literal_hosts = {target_host}
        modules: dict[Path, str] = {}
        root_uses_injected_target = False

        def inspect_module(module_path: Path, *, root: bool = False) -> None:
            nonlocal root_uses_injected_target
            module_path = self._workspace_module_path(module_path)
            relative_path = module_path.relative_to(self.workspace)
            if relative_path in modules:
                return
            if len(modules) >= _MAX_K6_MODULES:
                raise PermissionError(f"k6 import graph exceeds {_MAX_K6_MODULES} local modules")
            try:
                encoded = read_bytes_confined(
                    self.workspace,
                    relative_path,
                    max_bytes=_MAX_K6_MODULE_BYTES,
                    label="k6 module",
                    expected_root_identity=self._workspace_root_identity,
                )
            except FileNotFoundError as exc:
                if root:
                    raise PermissionError(
                        "k6 script must be an existing .js file inside the target workspace"
                    ) from exc
                raise PermissionError(
                    "k6 local imports must resolve to existing .js files inside the target workspace"
                ) from exc
            except RuntimeError as exc:
                raise PermissionError(
                    "k6 module ingestion requires descriptor-relative no-follow filesystem authority"
                ) from exc
            except (OSError, ValueError) as exc:
                raise PermissionError("k6 module failed confined no-follow ingestion") from exc
            try:
                source = encoded.decode("utf-8")
            except UnicodeError as exc:
                raise PermissionError("k6 module must be valid UTF-8") from exc
            modules[relative_path] = source
            if re.search(r"\bopen\s*\(", source):
                raise PermissionError("k6 scripts may not read local files through open()")
            if _COMMONJS_REQUIRE.search(source):
                raise PermissionError("k6 CommonJS require is not allowed in the controlled runner")
            if _DYNAMIC_IMPORT.search(source):
                raise PermissionError("k6 dynamic import() is not allowed in the controlled runner")
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
                    imported = module_path.parent / specifier
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
        return resolved.relative_to(self.workspace), modules

    def _validate_script(self, script: Path, target_url: str) -> Path:
        root_relative, _modules = self._collect_validated_modules(script, target_url)
        return self.workspace / root_relative

    @staticmethod
    def _module_snapshot_sha256(modules: dict[Path, str]) -> str:
        digest = hashlib.sha256()
        digest.update(_K6_SNAPSHOT_HASH_DOMAIN)
        for relative_path in sorted(modules, key=lambda path: path.as_posix()):
            path_bytes = relative_path.as_posix().encode("utf-8")
            source_bytes = modules[relative_path].encode("utf-8")
            digest.update(len(path_bytes).to_bytes(8, "big"))
            digest.update(path_bytes)
            digest.update(len(source_bytes).to_bytes(8, "big"))
            digest.update(source_bytes)
        return digest.hexdigest()

    @staticmethod
    def _write_validated_snapshot(snapshot_root: Path, modules: dict[Path, str]) -> None:
        for relative_path, source in modules.items():
            destination = snapshot_root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.encode("utf-8"))

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
        try:
            value = float(raw)
        except OverflowError as exc:
            raise RuntimeError(f"k6 metric {metric}.{key} exceeds the numeric bound") from exc
        if not math.isfinite(value):
            raise RuntimeError(f"k6 metric {metric}.{key} must be finite")
        return value

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

    def run(self, script: Path, *, target_url: str, environment: str) -> K6ExecutionMetrics:
        if not self.external_egress_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level egress enforcement; "
                "static JavaScript inspection is not a network sandbox"
            )
        decision = self.policy.authorize_performance_target(target_url, environment=environment)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(decision.reason)
        root_relative, modules = self._collect_validated_modules(script, target_url)
        module_snapshot_sha256 = self._module_snapshot_sha256(modules)
        if not self.external_process_isolation_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level process/filesystem isolation; "
                "static JavaScript inspection is not an execution sandbox"
            )
        if not self.external_module_isolation_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level module-loading isolation; "
                "validated JavaScript inspection cannot prove that runtime-loaded code is confined"
            )
        if not self.external_resource_limits_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level CPU/memory/process resource limits; "
                "wall-clock and output bounds are not a resource sandbox"
            )
        if not self.external_workload_limits_enforced:
            raise PermissionError(
                "k6 execution requires trusted infrastructure-level target workload limits; "
                "result thresholds do not bound virtual users, request concurrency, or request rate"
            )
        if shutil.which("k6") is None:
            raise RuntimeError("k6 is not installed; runtime validation is NOT_VERIFIED")

        data: dict[str, Any]
        with tempfile.TemporaryDirectory(prefix="aiqa-k6-runtime-") as temp_runtime:
            runtime_root = Path(temp_runtime)
            snapshot_root = runtime_root / "workspace"
            self._write_validated_snapshot(snapshot_root, modules)
            script_path = snapshot_root / root_relative
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
                    "K6_AUTO_EXTENSION_RESOLUTION": "false",
                },
            )
            result = run_bounded_subprocess(
                command,
                cwd=snapshot_root,
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
                data = read_json_object_bounded(
                    summary_path,
                    max_bytes=_MAX_K6_SUMMARY_BYTES,
                    label="k6 summary",
                )
            except (OSError, UnicodeError, ValueError) as exc:
                raise RuntimeError("k6 summary failed bounded unambiguous JSON ingestion") from exc

        metrics = self._parse_metrics(data)
        return K6ExecutionMetrics(
            **metrics.model_dump(mode="python"),
            module_snapshot_sha256=module_snapshot_sha256,
        )
