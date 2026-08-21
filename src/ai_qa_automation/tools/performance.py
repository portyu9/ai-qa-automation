from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from ..models import PerformanceMetrics, ToolDecision
from ..policy import PolicyEngine


class K6Runner:
    def __init__(self, workspace: Path, policy: PolicyEngine, timeout_seconds: int = 180) -> None:
        self.workspace = workspace.resolve()
        self.policy = policy
        self.timeout_seconds = timeout_seconds

    def run(self, script: Path, *, target_url: str, environment: str) -> PerformanceMetrics:
        decision = self.policy.authorize_performance_target(target_url, environment=environment)
        if decision.decision != ToolDecision.ALLOW:
            raise PermissionError(decision.reason)
        if shutil.which("k6") is None:
            raise RuntimeError("k6 is not installed; runtime validation is NOT_VERIFIED")
        summary_path = self.workspace / ".k6-summary.json"
        command = ["k6", "run", "--summary-export", str(summary_path), str(script)]
        result = subprocess.run(command, cwd=self.workspace, capture_output=True, text=True, timeout=self.timeout_seconds, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr[-3000:] or "k6 failed")
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
