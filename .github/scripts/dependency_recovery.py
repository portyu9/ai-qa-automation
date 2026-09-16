#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from dependency_governance import (
    BOT_LOGIN,
    BOT_USER_ID,
    GitHubApi,
    GovernanceError,
    PolicyBlock,
    assess,
    load_config,
    open_dependabot_prs,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RECOVERY_CONFIG = ROOT / ".github" / "dependency-recovery.json"
LOG_TIMESTAMP = re.compile(r"^\ufeff?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s")

TRANSIENT_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dns-eai-again", re.compile(r"\bEAI_AGAIN\b", re.I)),
    ("connection-reset", re.compile(r"\bECONNRESET\b", re.I)),
    ("connection-timeout", re.compile(r"\bETIMEDOUT\b", re.I)),
    ("socket-timeout", re.compile(r"\bERR_SOCKET_TIMEOUT\b", re.I)),
    ("network-unreachable", re.compile(r"\bENETUNREACH\b", re.I)),
    ("host-unreachable", re.compile(r"\bEHOSTUNREACH\b", re.I)),
    ("socket-hang-up", re.compile(r"\bsocket hang up\b", re.I)),
    ("http-5xx", re.compile(r"(?:status(?: code)?|HTTP(?:/\d(?:\.\d)?)?|server returned code)\s*[:=]?\s*(?:502|503|504)\b", re.I)),
    ("gateway-service-outage", re.compile(r"\b(?:502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout)\b", re.I)),
    ("tls-transient", re.compile(r"\bTLS\b.*\b(?:handshake|connection)\b.*\b(?:timeout|timed out|unexpected EOF)\b", re.I)),
)

NON_TRANSIENT_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pip-resolution-impossible", re.compile(r"\bResolutionImpossible\b", re.I)),
    ("pip-unsatisfied-requirement", re.compile(r"Could not find a version that satisfies the requirement", re.I)),
    ("pip-no-matching-distribution", re.compile(r"No matching distribution found", re.I)),
    ("pip-hash-mismatch", re.compile(r"(?:THESE PACKAGES DO NOT MATCH THE HASHES|HashMismatch|hashes? from the requirements file)", re.I)),
    ("pip-dependency-conflict", re.compile(r"(?:conflicting dependencies|dependency conflict|ResolutionTooDeep)", re.I)),
    ("http-client-or-policy", re.compile(r"(?:status(?: code)?|HTTP(?:/\d(?:\.\d)?)?|server returned code)\s*[:=]?\s*(?:400|401|403|404|409|422|429)\b", re.I)),
    ("permission-denied", re.compile(r"\b(?:EACCES|EPERM|Permission denied)\b", re.I)),
    ("disk-space", re.compile(r"\b(?:ENOSPC|No space left on device)\b", re.I)),
)

SAFE_POLICIES = {
    "portyu9/ai-qa-automation": {
        "workflow": "CI — ƳƤ AI QA Automation Framework",
        "aggregateJobs": {"Required PR Gate"},
        "steps": {
            "Set up Python",
            "Install hash-locked development graph",
            "Install hash-locked project environment",
            "Install hash-locked security environment",
            "Install hash-locked verification environment",
            "Upload deterministic test evidence",
            "Upload deterministic control evaluation evidence",
            "Upload supply-chain evidence",
            "Upload security scan metadata",
            "Upload browser test metadata",
        },
    },
    "portyu9/qa-automation-ai-agent-evals": {
        "workflow": "CI",
        "aggregateJobs": {"ci-gate"},
        "steps": {
            "Set up Python",
            "Install",
            "Install mutation test dependencies",
            "Install OpenAI adapter test dependencies",
            "Install MCP fault-lab test dependencies",
            "Install MCP remote-auth test dependencies",
            "Install MCP OAuth-flow test dependencies",
            "Upload mutation diagnostics",
            "Upload exact tested package artifacts",
        },
    },
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_recovery_config(path: Path | None = None) -> dict[str, Any]:
    config_path = path or Path(os.environ.get("RECOVERY_CONFIG", DEFAULT_RECOVERY_CONFIG))
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"unable to read recovery config {config_path}: {exc}") from exc
    errors = validate_recovery_config(config)
    if errors:
        raise GovernanceError("invalid dependency recovery config:\n- " + "\n- ".join(errors))
    return config


def validate_recovery_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    governance = load_config()
    repository = governance["repository"]
    safe = SAFE_POLICIES.get(repository)
    if safe is None:
        return [f"no code-owned recovery policy exists for {repository}"]
    if config.get("schemaVersion") != 1:
        errors.append("schemaVersion must equal 1")
    if not isinstance(config.get("enabled"), bool):
        errors.append("enabled must be boolean")
    if config.get("maxRunAttempts") != 2:
        errors.append("maxRunAttempts must equal 2 so recovery is capped at one rerun")
    if config.get("workflow") != safe["workflow"]:
        errors.append("workflow must equal the code-owned CI workflow")
    aggregates = config.get("aggregateJobs")
    if not isinstance(aggregates, list) or set(aggregates) != safe["aggregateJobs"]:
        errors.append("aggregateJobs must exactly match the code-owned aggregate set")
    steps = config.get("transientSteps")
    if not isinstance(steps, list) or not steps:
        errors.append("transientSteps must be a non-empty array")
    else:
        if any(not isinstance(step, str) or not step.strip() for step in steps):
            errors.append("every transientSteps entry must be a non-empty string")
        if len(set(steps)) != len(steps):
            errors.append("transientSteps must not contain duplicates")
        for step in steps:
            if step not in safe["steps"]:
                errors.append(f"{step} is outside the code-owned infrastructure recovery allowlist")
    return list(dict.fromkeys(errors))


def matching_transient_signatures(logs: str) -> list[str]:
    return [name for name, pattern in TRANSIENT_SIGNATURES if pattern.search(logs)]


def matching_non_transient_signatures(logs: str) -> list[str]:
    return [name for name, pattern in NON_TRANSIENT_SIGNATURES if pattern.search(logs)]


def extract_step_log_window(logs: str, step: dict[str, Any]) -> str | None:
    started = _parse_timestamp(step.get("started_at"))
    completed = _parse_timestamp(step.get("completed_at"))
    if started is None or completed is None or completed < started:
        return None
    selected: list[str] = []
    for line in logs.splitlines():
        match = LOG_TIMESTAMP.match(line)
        if match is None:
            continue
        timestamp = _parse_timestamp(match.group(1))
        if timestamp is not None and started <= timestamp <= completed:
            selected.append(line)
    return "\n".join(selected) if selected else None


def classify_failed_job(job: dict[str, Any], logs: str, config: dict[str, Any]) -> dict[str, Any]:
    if job.get("conclusion") != "failure":
        return {"transient": False, "reason": "job conclusion is not failure"}
    failed_steps = [step for step in (job.get("steps") or []) if step.get("conclusion") == "failure"]
    if len(failed_steps) != 1:
        return {"transient": False, "reason": f"expected exactly one failed step, found {len(failed_steps)}"}
    failed = failed_steps[0]
    name = str(failed.get("name") or "")
    if name not in config["transientSteps"]:
        return {"transient": False, "reason": f"failed step is outside recovery allowlist: {name}"}
    window = extract_step_log_window(logs, failed)
    if window is None:
        return {"transient": False, "reason": f"no timestamp-bounded log window for failed step: {name}"}
    blockers = matching_non_transient_signatures(window)
    if blockers:
        return {"transient": False, "reason": "deterministic/policy blocker outranks transient evidence", "blockers": blockers}
    transient = matching_transient_signatures(window)
    if not transient:
        return {"transient": False, "reason": "no approved transient signature in failed-step log window"}
    return {"transient": True, "failedStep": name, "signatures": transient}


def _fetch_job_logs(api: GitHubApi, job_id: int) -> str:
    path = f"/actions/jobs/{job_id}/logs"
    request = urllib.request.Request(
        f"{api.root}{path}",
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {api.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "dependabot-recovery",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code not in {301, 302, 303, 307, 308}:
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise GovernanceError(f"job log request failed HTTP {exc.code}: {detail}") from exc
        location = exc.headers.get("Location", "")
    else:
        raise GovernanceError("job log endpoint did not return the expected signed redirect")
    parsed = urllib.parse.urlsplit(location)
    host = (parsed.hostname or "").lower()
    allowed_host = host.endswith(".actions.githubusercontent.com") or host.endswith(".blob.core.windows.net")
    if parsed.scheme != "https" or not allowed_host or parsed.username or parsed.password or len(location) > 8192:
        raise GovernanceError("job log redirect target is not an approved GitHub Actions log host")
    unsigned = urllib.request.Request(location, method="GET", headers={"User-Agent": "dependabot-recovery"})
    try:
        with urllib.request.urlopen(unsigned, timeout=30) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise GovernanceError(f"unable to download redirected job logs: {exc}") from exc
    if len(raw) > 4 * 1024 * 1024:
        raise GovernanceError("job logs exceed bounded ingestion limit")
    return raw.decode("utf-8", errors="replace")


def _latest_failed_run(api: GitHubApi, head_sha: str, workflow: str) -> dict[str, Any] | None:
    encoded = urllib.parse.quote(head_sha, safe="")
    runs = api.list_all(f"/actions/runs?event=pull_request&head_sha={encoded}", max_pages=3)
    matching = [
        run
        for run in runs
        if run.get("name") == workflow
        and run.get("head_sha") == head_sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "failure"
        and (run.get("actor") or {}).get("login") == BOT_LOGIN
    ]
    if not matching:
        return None
    return max(matching, key=lambda row: int(row.get("id") or 0))


def _recover_run(api: GitHubApi, run: dict[str, Any], config: dict[str, Any]) -> bool:
    attempt = run.get("run_attempt")
    if not isinstance(attempt, int) or attempt < 1:
        raise GovernanceError("workflow run_attempt is invalid")
    if attempt >= config["maxRunAttempts"]:
        print(f"recovery blocked: run attempt {attempt} reached cap {config['maxRunAttempts']}")
        return False
    run_id = run.get("id")
    if not isinstance(run_id, int) or run_id < 1:
        raise GovernanceError("workflow run id is invalid")
    jobs = api.list_all(f"/actions/runs/{run_id}/jobs?filter=latest", max_pages=3)
    aggregate_names = set(config["aggregateJobs"])
    failed_leaf: list[dict[str, Any]] = []
    for job in jobs:
        if job.get("status") != "completed":
            print(f"recovery blocked: job is not terminal: {job.get('name')}")
            return False
        conclusion = job.get("conclusion")
        name = str(job.get("name") or "")
        if conclusion == "failure" and name not in aggregate_names:
            failed_leaf.append(job)
        elif conclusion not in {"success", "skipped", "neutral", "failure"}:
            print(f"recovery blocked: non-retriable job conclusion {name}={conclusion}")
            return False
        elif conclusion == "failure" and name not in aggregate_names:
            return False
    if len(failed_leaf) != 1:
        print(f"recovery blocked: expected one failed leaf job, found {len(failed_leaf)}")
        return False
    job = failed_leaf[0]
    job_id = job.get("id")
    if not isinstance(job_id, int) or job_id < 1:
        raise GovernanceError("failed job id is invalid")
    decision = classify_failed_job(job, _fetch_job_logs(api, job_id), config)
    if decision.get("transient") is not True:
        print(json.dumps({"recovery": "blocked", "job": job.get("name"), **decision}, sort_keys=True))
        return False
    api.post(f"/actions/jobs/{job_id}/rerun")
    print(json.dumps({"recovery": "rerun-requested", "job": job.get("name"), "jobId": job_id, **decision}, sort_keys=True))
    return True


def recover(config: dict[str, Any], recovery: dict[str, Any]) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise GovernanceError("workflow repository does not match bound governance config")
    if not recovery["enabled"]:
        print("dependency recovery is disabled")
        return 0
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    count = 0
    for summary in open_dependabot_prs(api):
        number = summary.get("number")
        try:
            live = api.get(f"/pulls/{number}")
            subject = assess(api, live, config, require_checks=False)
        except PolicyBlock as exc:
            print(json.dumps({"pr": number, "recovery": "blocked", "reason": str(exc)}, sort_keys=True))
            continue
        run = _latest_failed_run(api, subject["headSha"], recovery["workflow"])
        if run is None:
            continue
        if _recover_run(api, run, recovery):
            count += 1
    return count


def selftest(recovery: dict[str, Any]) -> None:
    errors = validate_recovery_config(recovery)
    if errors:
        raise GovernanceError("recovery config self-test failed: " + "; ".join(errors))
    mutated = dict(recovery)
    mutated["maxRunAttempts"] = 3
    if not validate_recovery_config(mutated):
        raise GovernanceError("recovery validator accepted more than one automatic rerun")
    mutated = dict(recovery)
    mutated["transientSteps"] = [*recovery["transientSteps"], "Run tests"]
    if not validate_recovery_config(mutated):
        raise GovernanceError("recovery validator accepted an arbitrary functional step")
    if not matching_transient_signatures("2026-01-01T00:00:00Z request failed: ECONNRESET"):
        raise GovernanceError("transient signature self-test failed")
    if not matching_non_transient_signatures("2026-01-01T00:00:00Z ResolutionImpossible"):
        raise GovernanceError("deterministic blocker self-test failed")
    print("dependency-recovery self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded Dependabot transient recovery")
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--recover", action="store_true")
    args = parser.parse_args()
    recovery = load_recovery_config()
    if args.validate_config:
        print("dependency-recovery config: valid")
    if args.self_test:
        selftest(recovery)
    if args.recover:
        recover(load_config(), recovery)
    if not (args.validate_config or args.self_test or args.recover):
        parser.error("choose --validate-config, --self-test, or --recover")


if __name__ == "__main__":
    main()
