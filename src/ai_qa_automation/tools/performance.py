from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from ..models import PerformanceMetrics, ToolDecision
from ..policy import PolicyEngine
from .execution_env import restricted_subprocess_env

_URL_LITERAL = re.compile(r"https?://[^'\"`\s)]+", re.I)
_IMPORT_SPECIFIER = re.compile(
    r"(?:from\s+|import\s*\(\s*|import\s+)([\'\"])([^\'\"]+)\1"
)
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
        if timeout_seconds < 1:
            raise ValueError("k6 timeout_seconds must be positive")
        self.workspace = workspace.resolve()
        self.policy = policy
        self.timeout_seconds = timeout_seconds
        self.external_egress_enforced = external_egress_enforced

    def _validate_script(self, script: Path, target_url: str) -> Path:
        resolved = (script if script.is_absolute() else self.workspace / script).resolve()
        if self.workspace not in resolved.parents or resolved.suffix != ".js" or not resolved.is_file():
            raise PermissionError("k6 script must be an existing .js file inside the target workspace")
        target_host = (urlparse(target_url).hostname or "").lower()
        allowed_literal_hosts = {target_host, "localhost", "127.0.0.1", "::1"}
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
                raise PermissionError("k6 local imports must resolve to .js files inside the target workspace")
            if len(visited) >= _MAX_K6_MODULES:
                raise PermissionError(f"k6 import graph exceeds {_MAX_K6_MODULES} local modules")
            if module_path.stat().st_size > _MAX_K6_MODULE_BYTES:
                raise PermissionError(f"k6 module exceeds {_MAX_K6_MODULE_BYTES} byte limit")
            visited.add(module_path)
            source = module_path.read_text(encoding="utf-8")
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
                    raise PermissionError("k6 extension modules are not allowed in the controlled runner")
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
            try:
                result = subprocess.run(
                    command,
                    cwd=self.workspace,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    env=env,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"k6 exceeded {self.timeout_seconds}s execution budget"
                ) from exc
            if result.returncode != 0:
                raise RuntimeError(result.stderr[-3000:] or "k6 failed")
            if not summary_path.is_file():
                raise RuntimeError("k6 completed without producing the required summary artifact")
            if summary_path.stat().st_size > _MAX_K6_SUMMARY_BYTES:
                raise RuntimeError(
                    f"k6 summary exceeds {_MAX_K6_SUMMARY_BYTES} byte ingestion limit"
                )
            data = json.loads(summary_path.read_text(encoding="utf-8"))

        duration = data["metrics"]["http_req_duration"]["values"]
        return PerformanceMetrics(
            p50_ms=float(duration.get("med", 0)),
            p90_ms=float(duration.get("p(90)", 0)),
            p95_ms=float(duration.get("p(95)", 0)),
            p99_ms=float(duration.get("p(99)", duration.get("max", 0))),
            request_rate=float(data["metrics"]["http_reqs"]["values"].get("rate", 0)),
            error_rate=float(data["metrics"]["http_req_failed"]["values"].get("rate", 0)),
        )
