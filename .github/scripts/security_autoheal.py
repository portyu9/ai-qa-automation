#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "security-autoheal.json"
API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282
MARKER_PREFIX = "<!-- aiqa-codeql-autoheal:"
MARKER_SUFFIX = " -->"
BRANCH_PREFIX = "automation/codeql-autoheal-"
AUTOHEAL_BRANCH_RE = re.compile(
    r"^automation/codeql-autoheal-[1-9][0-9]*-[0-9a-f]{12}$"
)
AUTOHEAL_COMMIT_MESSAGE_RE = re.compile(r"^security: auto-heal CodeQL alert #[1-9][0-9]*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SAFE_RULES = {
    "py/reflective-xss",
    "py/incomplete-url-substring-sanitization",
    "py/clear-text-logging-sensitive-data",
    "py/overly-permissive-file",
}
SAFE_VERIFIER_LABELS = {
    "scripts/auto_trusted_report.py": "trusted-pr-gate",
    "scripts/ci_contract_base.py": "ci-contract-base",
    "scripts/verify_ci_contract.py": "ci-contract",
    "scripts/verify_docs.py": "documentation-integrity",
    "scripts/verify_fork_cloud_authority.py": "fork-cloud-authority",
}

DETERMINISTIC_LOG_REPAIRS = {
    "scripts/auto_trusted_report.py": (
        "    print(json.dumps(result, indent=2, sort_keys=True))",
        '    print(json.dumps({"result": result["result"], "reporter": "trusted-pr-gate"}, sort_keys=True))',
    ),
    "scripts/ci_contract_base.py": (
        "    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))",
        '    verify_ci_contract(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "ci-contract-base"}, sort_keys=True))',
    ),
    "scripts/verify_ci_contract.py": (
        "    print(json.dumps(verify_ci_contract(root), indent=2, sort_keys=True))",
        '    verify_ci_contract(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "ci-contract"}, sort_keys=True))',
    ),
    "scripts/verify_docs.py": (
        "    print(json.dumps(verify_documentation(root), indent=2, sort_keys=True))",
        '    verify_documentation(root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "documentation-integrity"}, sort_keys=True))',
    ),
    "scripts/verify_fork_cloud_authority.py": (
        '    print(json.dumps(verify_repository(args.root), sort_keys=True, separators=(",", ":")))',
        '    verify_repository(args.root)\n    print(json.dumps({"schema_version": 1, "result": "PASS", "verifier": "fork-cloud-authority"}, separators=(",", ":"), sort_keys=True))',
    ),
}


class AutohealError(RuntimeError):
    """Operational/configuration failure that must fail the workflow."""


class PolicyBlock(RuntimeError):
    """Expected fail-closed decision for one alert or repair candidate."""


class RetryLater(RuntimeError):
    """Expected non-failure state while GitHub is generating an autofix."""


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _path_matches(path: str, protected: str) -> bool:
    if protected.endswith("/"):
        return path.startswith(protected)
    return path == protected


def validate_config(config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if config.get("schemaVersion") != 1:
        errors.append("schemaVersion must equal 1")
    if config.get("repository") != "portyu9/ai-qa-automation":
        errors.append("repository must equal portyu9/ai-qa-automation")
    if config.get("baseBranch") != "main":
        errors.append("baseBranch must equal main")
    if config.get("enabled") is not True:
        errors.append("enabled must be true")
    if config.get("automergeEnabled") is not True:
        errors.append("automergeEnabled must be true")
    if config.get("mergeMethod") != "merge":
        errors.append("mergeMethod must equal merge")
    severity = config.get("minimumSecuritySeverity")
    if not isinstance(severity, (int, float)) or isinstance(severity, bool) or severity < 7.0:
        errors.append("minimumSecuritySeverity must be numeric and at least 7.0")
    for key, upper in (
        ("maxChangedFiles", 10),
        ("maxOpenRepairs", 10),
        ("maxAttemptsPerAlert", 3),
    ):
        value = config.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= upper):
            errors.append(f"{key} must be an integer from 1 to {upper}")
    checks = config.get("requiredChecks")
    if checks != ["Required PR Gate", "CodeQL"]:
        errors.append("requiredChecks must equal Required PR Gate and CodeQL")
    if config.get("trustedStatusContext") != "Trusted PR Gate":
        errors.append("trustedStatusContext must equal Trusted PR Gate")
    rules = config.get("allowedRules")
    if not isinstance(rules, list) or set(rules) != SAFE_RULES:
        errors.append("allowedRules must equal the code-owned four-rule allowlist")
    for key in ("modelAutofixPathPrefixes", "deterministicOnlyPaths", "neverModifyPaths"):
        values = config.get(key)
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) and value for value in values)
        ):
            errors.append(f"{key} must be a non-empty string list")
    never = config.get("neverModifyPaths")
    if isinstance(never, list):
        for required in (
            ".github/",
            "scripts/auto_trusted_preflight.py",
            "scripts/trusted_pr_control.py",
        ):
            if required not in never:
                errors.append(f"neverModifyPaths must include {required}")
    deterministic = config.get("deterministicOnlyPaths")
    if isinstance(deterministic, list):
        for required in SAFE_VERIFIER_LABELS:
            if required not in deterministic:
                errors.append(f"deterministicOnlyPaths must include {required}")
    return _unique(errors)


def load_config(path: Path | None = None) -> dict[str, Any]:
    target = path or Path(os.environ.get("SECURITY_AUTOHEAL_CONFIG", DEFAULT_CONFIG))
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutohealError(f"unable to read security auto-heal config: {exc}") from exc
    if not isinstance(payload, dict):
        raise AutohealError("security auto-heal config must be an object")
    errors = validate_config(payload)
    if errors:
        raise AutohealError("invalid security auto-heal config:\n- " + "\n- ".join(errors))
    return payload


def _validate_api_path(path: str) -> None:
    parsed = urllib.parse.urlsplit(path)
    decoded_path = urllib.parse.unquote(parsed.path)
    segments = decoded_path.split("/")
    if (
        not path.startswith("/")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or "\\" in decoded_path
        or "\x00" in decoded_path
        or any(segment in {".", ".."} for segment in segments)
    ):
        raise AutohealError("GitHub API path must be absolute and repository-local")


class GitHubApi:
    def __init__(self, token: str, repository: str) -> None:
        if not token:
            raise AutohealError("GITHUB_TOKEN is required")
        if repository != "portyu9/ai-qa-automation":
            raise AutohealError("repository is not the code-owned auto-heal repository")
        self.token = token
        self.repository = repository
        self.root = f"{API_ROOT}/repos/{repository}"

    def request_status(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> tuple[int, Any]:
        _validate_api_path(path)
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = urllib.request.Request(
            f"{self.root}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token or self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "aiqa-codeql-autoheal",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = int(response.status)
                raw = response.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            raise AutohealError(
                f"GitHub API {method} {path} failed HTTP {exc.code}: {detail[:1000]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise AutohealError(f"GitHub API {method} {path} transport failure: {exc}") from exc
        if len(raw) > max_bytes:
            raise AutohealError(f"GitHub API {method} {path} exceeded bounded response size")
        if not raw:
            return status, None
        try:
            return status, json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AutohealError(f"GitHub API {method} {path} returned malformed JSON") from exc

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        return self.request_status(method, path, payload, token=token)[1]

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        token: str | None = None,
    ) -> Any:
        return self.request("POST", path, payload, token=token)

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PATCH", path, payload)

    def put(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PUT", path, payload)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if isinstance(payload, dict):
                items = None
                for collection_key in ("check_runs", "workflow_runs"):
                    if collection_key in payload:
                        items = payload[collection_key]
                        break
            else:
                items = payload
            if not isinstance(items, list):
                raise AutohealError(f"unexpected paginated response for {path}")
            rows.extend(item for item in items if isinstance(item, dict))
            if len(items) < 100:
                return rows
        raise AutohealError(f"pagination limit reached for {path}")


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise PolicyBlock(f"{label} is not a canonical 40-character SHA")
    return value


def _current_main(api: GitHubApi, config: dict[str, Any]) -> str:
    branch = api.get(f"/branches/{urllib.parse.quote(config['baseBranch'], safe='')}")
    return _require_sha(((branch or {}).get("commit") or {}).get("sha"), "live main SHA")


SECURITY_SEVERITY_FLOORS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}


def _security_severity(alert: dict[str, Any]) -> float:
    rule = alert.get("rule") or {}
    value = rule.get("security_severity")
    if value is not None:
        try:
            severity = float(value)
        except (TypeError, ValueError) as exc:
            raise PolicyBlock("CodeQL alert has malformed numeric security severity") from exc
        if severity < 0 or severity > 10:
            raise PolicyBlock("CodeQL security severity is outside 0..10")
        return severity

    level = rule.get("security_severity_level")
    if isinstance(level, str):
        severity = SECURITY_SEVERITY_FLOORS.get(level.lower())
        if severity is not None:
            return severity
    raise PolicyBlock("CodeQL alert lacks a supported security severity")


def _alert_location(alert: dict[str, Any]) -> tuple[str, int]:
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    path = location.get("path")
    line = location.get("start_line")
    if (
        not isinstance(path, str)
        or not path.endswith(".py")
        or path.startswith("/")
        or ".." in Path(path).parts
    ):
        raise PolicyBlock("CodeQL alert path is not a safe repository Python path")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise PolicyBlock("CodeQL alert start line is invalid")
    return path, line


def _alert_fingerprint(alert: dict[str, Any], main_sha: str) -> str:
    rule = alert.get("rule") or {}
    instance = alert.get("most_recent_instance") or {}
    message = (instance.get("message") or {}).get("text") or ""
    path, line = _alert_location(alert)
    material = "\0".join(
        (
            str(alert.get("number")),
            str(rule.get("id")),
            path,
            str(line),
            str(message),
            main_sha,
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def validate_alert(alert: dict[str, Any], main_sha: str, config: dict[str, Any]) -> dict[str, Any]:
    number = alert.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise PolicyBlock("CodeQL alert number is invalid")
    if alert.get("state") != "open":
        raise PolicyBlock("CodeQL alert is not open")
    if (alert.get("tool") or {}).get("name") != "CodeQL":
        raise PolicyBlock("security auto-heal accepts only CodeQL alerts")
    rule_id = (alert.get("rule") or {}).get("id")
    if rule_id not in set(config["allowedRules"]):
        raise PolicyBlock(f"CodeQL rule is outside the code-owned allowlist: {rule_id}")
    severity = _security_severity(alert)
    if severity < float(config["minimumSecuritySeverity"]):
        raise PolicyBlock("CodeQL alert is below the automatic remediation severity floor")
    instance = alert.get("most_recent_instance") or {}
    if instance.get("ref") != "refs/heads/main":
        raise PolicyBlock("latest CodeQL alert instance is not bound to main")
    if _require_sha(instance.get("commit_sha"), "alert instance SHA") != main_sha:
        raise PolicyBlock("latest CodeQL alert instance is stale relative to current main")
    path, line = _alert_location(alert)
    if any(_path_matches(path, blocked) for blocked in config["neverModifyPaths"]):
        raise PolicyBlock(f"alert targets a never-modify control-plane path: {path}")
    return {
        "number": number,
        "rule": rule_id,
        "severity": severity,
        "path": path,
        "line": line,
        "baseSha": main_sha,
        "fingerprint": _alert_fingerprint(alert, main_sha),
    }


def _marker(metadata: dict[str, Any]) -> str:
    return (
        MARKER_PREFIX + json.dumps(metadata, separators=(",", ":"), sort_keys=True) + MARKER_SUFFIX
    )


def _parse_marker(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, str):
        return None
    for line in body.splitlines():
        if line.startswith(MARKER_PREFIX) and line.endswith(MARKER_SUFFIX):
            raw = line[len(MARKER_PREFIX) : -len(MARKER_SUFFIX)]
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _branch_name(subject: dict[str, Any]) -> str:
    return f"{BRANCH_PREFIX}{subject['number']}-{subject['fingerprint'][:12]}"


def _is_deterministic_only(path: str, config: dict[str, Any]) -> bool:
    return any(_path_matches(path, value) for value in config["deterministicOnlyPaths"])


def _model_path_allowed(path: str, config: dict[str, Any]) -> bool:
    return any(path.startswith(prefix) for prefix in config["modelAutofixPathPrefixes"])


def _deterministic_repair(subject: dict[str, Any]) -> str | None:
    path = ROOT / subject["path"]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyBlock(f"alert source cannot be read safely: {exc}") from exc
    lines = text.splitlines(keepends=True)
    center = min(max(int(subject["line"]) - 1, 0), max(len(lines) - 1, 0))
    window = range(max(0, center - 5), min(len(lines), center + 6))

    if subject["rule"] == "py/overly-permissive-file" and subject["path"].startswith("tests/"):
        candidates = [index for index in window if "0o777" in lines[index]]
        if len(candidates) != 1:
            return None
        index = candidates[0]
        lines[index] = lines[index].replace("0o777", "0o600", 1)
        return "".join(lines)

    if (
        subject["rule"] == "py/clear-text-logging-sensitive-data"
        and subject["path"] in DETERMINISTIC_LOG_REPAIRS
    ):
        old, new = DETERMINISTIC_LOG_REPAIRS[subject["path"]]
        if text.count(old) != 1:
            return None
        return text.replace(old, new, 1)

    return None


def _git_commit(api: GitHubApi, sha: str) -> dict[str, Any]:
    payload = api.get(f"/git/commits/{sha}")
    if not isinstance(payload, dict):
        raise AutohealError("GitHub returned invalid commit metadata")
    return payload


def _create_branch(api: GitHubApi, branch: str, base_sha: str) -> None:
    encoded = urllib.parse.quote(branch, safe="")
    try:
        existing = api.get(f"/git/ref/heads/{encoded}")
    except AutohealError as exc:
        if "HTTP 404" not in str(exc):
            raise
    else:
        observed = _require_sha(
            ((existing or {}).get("object") or {}).get("sha"), "existing branch SHA"
        )
        if observed == base_sha:
            return
        api.delete(f"/git/refs/heads/{encoded}")
    created = api.post("/git/refs", {"ref": f"refs/heads/{branch}", "sha": base_sha})
    if not isinstance(created, dict) or created.get("ref") != f"refs/heads/{branch}":
        raise AutohealError("GitHub did not acknowledge auto-heal branch creation")


def _commit_deterministic_repair(
    api: GitHubApi,
    branch: str,
    base_sha: str,
    path: str,
    content: str,
    alert_number: int,
) -> str:
    base_commit = _git_commit(api, base_sha)
    tree = base_commit.get("tree") or {}
    base_tree = _require_sha(tree.get("sha"), "base tree SHA")
    created_tree = api.post(
        "/git/trees",
        {
            "base_tree": base_tree,
            "tree": [{"path": path, "mode": "100644", "type": "blob", "content": content}],
        },
    )
    tree_sha = _require_sha((created_tree or {}).get("sha"), "generated repair tree SHA")
    commit = api.post(
        "/git/commits",
        {
            "message": f"security: auto-heal CodeQL alert #{alert_number}",
            "tree": tree_sha,
            "parents": [base_sha],
        },
    )
    head_sha = _require_sha((commit or {}).get("sha"), "generated repair commit SHA")
    encoded = urllib.parse.quote(branch, safe="")
    updated = api.patch(f"/git/refs/heads/{encoded}", {"sha": head_sha, "force": False})
    if (
        _require_sha(((updated or {}).get("object") or {}).get("sha"), "updated repair ref SHA")
        != head_sha
    ):
        raise AutohealError("generated repair branch did not advance to the exact repair commit")
    return head_sha


def _ensure_copilot_autofix(api: GitHubApi, alert_number: int) -> None:
    path = f"/code-scanning/alerts/{alert_number}/autofix"
    status, payload = api.request_status("POST", path)
    state = (payload or {}).get("status") if isinstance(payload, dict) else None
    if status == 200 and state == "success":
        return
    if status not in {200, 202}:
        raise PolicyBlock(f"GitHub CodeQL Autofix is unavailable: status={status} state={state}")
    if status == 200 and state not in {"pending", "in_progress", "queued"}:
        raise PolicyBlock(f"GitHub CodeQL Autofix is unavailable: status={status} state={state}")

    for _ in range(10):
        time.sleep(3)
        poll_status, poll_payload = api.request_status("GET", path)
        poll_state = (poll_payload or {}).get("status") if isinstance(poll_payload, dict) else None
        if poll_status == 200 and poll_state == "success":
            return
        if poll_status == 404 or (
            poll_status == 200 and poll_state in {"pending", "in_progress", "queued"}
        ):
            continue
        raise PolicyBlock(
            f"GitHub CodeQL Autofix status is unavailable: status={poll_status} state={poll_state}"
        )
    raise RetryLater("GitHub CodeQL Autofix is still generating a proposal")


def _commit_copilot_autofix(api: GitHubApi, alert_number: int, branch: str, base_sha: str) -> str:
    _create_branch(api, branch, base_sha)
    payload = api.post(
        f"/code-scanning/alerts/{alert_number}/autofix/commits",
        {
            "target_ref": f"refs/heads/{branch}",
            "message": f"security: auto-heal CodeQL alert #{alert_number}",
        },
    )
    head_sha = _require_sha((payload or {}).get("sha"), "Copilot Autofix commit SHA")
    commit = _git_commit(api, head_sha)
    parents = commit.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise PolicyBlock("Copilot Autofix commit must have exactly one parent")
    if _require_sha((parents[0] or {}).get("sha"), "Copilot Autofix parent SHA") != base_sha:
        raise PolicyBlock("Copilot Autofix commit is not parented to exact current main")
    return head_sha


def _changed_files(api: GitHubApi, base_sha: str, head_sha: str) -> list[dict[str, Any]]:
    payload = api.get(f"/compare/{base_sha}...{head_sha}")
    files = (payload or {}).get("files")
    if not isinstance(files, list) or not files:
        raise PolicyBlock("repair candidate has no changed files")
    return [row for row in files if isinstance(row, dict)]


def _validate_candidate_diff(
    files: list[dict[str, Any]],
    subject: dict[str, Any],
    config: dict[str, Any],
    *,
    deterministic: bool,
) -> None:
    if len(files) > config["maxChangedFiles"]:
        raise PolicyBlock("repair candidate exceeds the automatic changed-file limit")
    paths: list[str] = []
    for row in files:
        path = row.get("filename")
        if not isinstance(path, str) or not path:
            raise PolicyBlock("repair candidate contains an invalid changed path")
        paths.append(path)
        if any(_path_matches(path, blocked) for blocked in config["neverModifyPaths"]):
            raise PolicyBlock(f"repair candidate touched never-modify control plane: {path}")
        if deterministic:
            if path != subject["path"]:
                raise PolicyBlock("deterministic repair may modify only the alert source file")
        elif not _model_path_allowed(path, config):
            raise PolicyBlock(f"model-generated repair touched non-model path: {path}")
    if subject["path"] not in paths:
        raise PolicyBlock("repair candidate does not modify the alert source file")


def _github_actions_pr_creation_denied(exc: Exception) -> bool:
    detail = str(exc)
    return (
        "HTTP 403" in detail
        and "GitHub Actions is not permitted to create or approve pull requests" in detail
    )


def _delete_exact_generated_branch(api: GitHubApi, branch: str, head_sha: str) -> None:
    encoded = urllib.parse.quote(branch, safe="")
    ref = api.get(f"/git/ref/heads/{encoded}")
    observed = _require_sha(
        ((ref or {}).get("object") or {}).get("sha"),
        "generated repair branch SHA before cleanup",
    )
    if observed != head_sha:
        raise PolicyBlock("generated repair branch changed before denied-PR cleanup")
    api.delete(f"/git/refs/heads/{encoded}")


def _create_pull_request(
    api: GitHubApi,
    branch: str,
    head_sha: str,
    subject: dict[str, Any],
    attempt: int,
    *,
    deterministic: bool,
) -> int:
    metadata = {
        "version": 1,
        "alert": subject["number"],
        "rule": subject["rule"],
        "severity": subject["severity"],
        "path": subject["path"],
        "base": subject["baseSha"],
        "head": head_sha,
        "fingerprint": subject["fingerprint"],
        "attempt": attempt,
        "generator": "deterministic" if deterministic else "github-codeql-autofix",
    }
    body = "\n".join(
        (
            _marker(metadata),
            "Automated remediation for an exact-main CodeQL alert.",
            "",
            "This pull request is machine-generated and must pass exact-subject CI, CodeQL,",
            "candidate-alert regression checks, and the App-owned Trusted PR Gate before merge.",
        )
    )
    try:
        pr = api.post(
            "/pulls",
            {
                "title": f"security: auto-heal CodeQL alert #{subject['number']}",
                "head": branch,
                "base": "main",
                "body": body,
                "draft": False,
            },
        )
    except AutohealError as exc:
        if not _github_actions_pr_creation_denied(exc):
            raise
        _delete_exact_generated_branch(api, branch, head_sha)
        raise AutohealError(
            "repository Actions policy blocks generated pull-request creation; "
            "enable 'Allow GitHub Actions to create and approve pull requests'"
        ) from exc
    number = (pr or {}).get("number")
    if not isinstance(number, int) or number < 1:
        raise AutohealError("GitHub did not acknowledge the generated repair pull request")
    observed_head = _require_sha(((pr or {}).get("head") or {}).get("sha"), "generated PR head SHA")
    if observed_head != head_sha:
        raise AutohealError("generated repair PR head differs from the exact repair commit")
    return number


def _dispatch_qualification(api: GitHubApi, branch: str, head_sha: str) -> None:
    subject_sha = _require_sha(head_sha, "generated repair qualification SHA")
    if AUTOHEAL_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("generated repair qualification ref is outside reviewed authority")
    api.post(
        "/actions/workflows/ci.yml/dispatches",
        {"ref": branch, "inputs": {"subject_sha": subject_sha}},
    )
    api.post("/actions/workflows/codeql.yml/dispatches", {"ref": branch})


def _latest_checks(api: GitHubApi, head_sha: str) -> dict[str, dict[str, Any]]:
    rows = api.list_all(f"/commits/{head_sha}/check-runs?filter=latest", max_pages=4)
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        stamp = row.get("completed_at") or row.get("started_at") or ""
        prior = latest.get(name)
        prior_stamp = (prior or {}).get("completed_at") or (prior or {}).get("started_at") or ""
        if prior is None or stamp >= prior_stamp:
            latest[name] = row
    return latest


def _require_green_checks(api: GitHubApi, head_sha: str, config: dict[str, Any]) -> None:
    checks = _latest_checks(api, head_sha)
    for name in config["requiredChecks"]:
        row = checks.get(name)
        if row is None:
            raise PolicyBlock(f"repair required check has not registered: {name}")
        if row.get("status") != "completed" or row.get("conclusion") != "success":
            raise PolicyBlock(
                f"repair required check is not green: {name} "
                f"status={row.get('status')} conclusion={row.get('conclusion')}"
            )


def _alert_shape(alert: dict[str, Any]) -> tuple[str, str, str]:
    rule_id = str((alert.get("rule") or {}).get("id") or "")
    instance = alert.get("most_recent_instance") or {}
    location = instance.get("location") or {}
    message = instance.get("message") or {}
    return rule_id, str(location.get("path") or ""), str(message.get("text") or "")


def _branch_alerts(api: GitHubApi, ref: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"state": "open", "ref": ref, "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    return api.list_all(f"/code-scanning/alerts?{query}", max_pages=10)


def _verify_codeql_remediation(
    api: GitHubApi, metadata: dict[str, Any], config: dict[str, Any]
) -> None:
    branch = str(metadata["branch"])
    alert_number = int(metadata["alert"])
    instances_query = urllib.parse.urlencode(
        {"ref": f"refs/heads/{branch}"}, quote_via=urllib.parse.quote
    )
    instances = api.list_all(
        f"/code-scanning/alerts/{alert_number}/instances?{instances_query}", max_pages=4
    )
    if instances:
        raise PolicyBlock("original CodeQL alert still has an instance on the repair branch")

    baseline = _branch_alerts(api, "refs/heads/main")
    candidate = _branch_alerts(api, f"refs/heads/{branch}")
    baseline_shapes = {_alert_shape(alert) for alert in baseline}
    threshold = float(metadata["severity"])
    for alert in candidate:
        if _security_severity(alert) < threshold:
            continue
        if _alert_shape(alert) not in baseline_shapes:
            raise PolicyBlock(
                "repair branch introduced a new CodeQL alert at equal/higher security severity"
            )


def _validate_generated_pr(
    api: GitHubApi, pr: dict[str, Any], config: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata = _parse_marker(pr.get("body"))
    if metadata is None or metadata.get("version") != 1:
        raise PolicyBlock("generated repair PR lacks the exact auto-heal marker")
    if (pr.get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN:
        raise PolicyBlock("generated repair PR author is not GitHub Actions")
    if (pr.get("user") or {}).get("id") != GITHUB_ACTIONS_USER_ID:
        raise PolicyBlock("generated repair PR user id is not canonical GitHub Actions")
    if pr.get("state") != "open" or pr.get("draft") is not False or pr.get("mergeable") is not True:
        raise PolicyBlock("generated repair PR is not open, non-draft, and definitively mergeable")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (head.get("repo") or {}).get("full_name") != config["repository"]:
        raise PolicyBlock("generated repair head is not repository-owned")
    if (base.get("repo") or {}).get("full_name") != config["repository"] or base.get(
        "ref"
    ) != "main":
        raise PolicyBlock("generated repair no longer targets repository main")
    branch = head.get("ref")
    if not isinstance(branch, str) or AUTOHEAL_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("generated repair branch name is outside the code-owned namespace")
    main_sha = _current_main(api, config)
    base_sha = _require_sha(base.get("sha"), "repair PR base SHA")
    if base_sha != main_sha or metadata.get("base") != main_sha:
        raise PolicyBlock("generated repair is stale relative to current main")
    head_sha = _require_sha(head.get("sha"), "repair PR head SHA")
    if metadata.get("head") != head_sha:
        raise PolicyBlock("generated repair head changed after qualification dispatch")
    if metadata.get("branch") not in {None, branch}:
        raise PolicyBlock("generated repair marker branch does not match live branch")
    metadata["branch"] = branch
    files = _changed_files(api, main_sha, head_sha)
    deterministic = metadata.get("generator") == "deterministic"
    subject = {
        "path": metadata.get("path"),
        "number": metadata.get("alert"),
    }
    _validate_candidate_diff(files, subject, config, deterministic=deterministic)
    return metadata, {"headSha": head_sha, "baseSha": base_sha, "branch": branch}


def _post_trusted_status(
    api: GitHubApi,
    pr_number: int,
    metadata: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> None:
    token = os.environ.get("TRUSTED_STATUS_TOKEN", "")
    if not token:
        raise AutohealError(
            "TRUSTED_STATUS_TOKEN is required for security auto-heal merge authority"
        )
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not run_id.isdigit() or int(run_id) < 1:
        raise AutohealError("GITHUB_RUN_ID is invalid")
    fresh = api.get(f"/pulls/{pr_number}")
    rebound_metadata, rebound_live = _validate_generated_pr(api, fresh, config)
    if rebound_metadata != metadata or rebound_live != live:
        raise PolicyBlock("repair PR changed before trusted status publication")
    _require_green_checks(api, live["headSha"], config)
    _verify_codeql_remediation(api, metadata, config)
    response = api.post(
        f"/statuses/{live['headSha']}",
        {
            "state": "success",
            "context": config["trustedStatusContext"],
            "description": "CodeQL exact-subject remediation passed",
            "target_url": f"https://github.com/{config['repository']}/actions/runs/{run_id}",
        },
        token=token,
    )
    if not isinstance(response, dict) or response.get("state") != "success":
        raise AutohealError("dedicated Trusted PR Gate status publication was not acknowledged")


def _merge(
    api: GitHubApi,
    pr_number: int,
    metadata: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> None:
    fresh = api.get(f"/pulls/{pr_number}")
    rebound_metadata, rebound_live = _validate_generated_pr(api, fresh, config)
    if rebound_metadata != metadata or rebound_live != live:
        raise PolicyBlock("repair PR changed before guarded merge")
    _require_green_checks(api, live["headSha"], config)
    _verify_codeql_remediation(api, metadata, config)
    result = api.put(
        f"/pulls/{pr_number}/merge",
        {"sha": live["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        message = result.get("message") if isinstance(result, dict) else result
        raise AutohealError(f"GitHub declined security auto-heal merge: {message}")


def _open_pulls(api: GitHubApi) -> list[dict[str, Any]]:
    return api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)


def _owned_generated_repair_commit(payload: Any, head_sha: str) -> bool:
    if not isinstance(payload, dict) or payload.get("sha") != head_sha:
        return False
    author = payload.get("author") or {}
    commit = payload.get("commit") or {}
    message = commit.get("message")
    if not isinstance(message, str) or not message:
        return False
    first_line = message.splitlines()[0]
    return (
        author.get("login") == GITHUB_ACTIONS_LOGIN
        and author.get("id") == GITHUB_ACTIONS_USER_ID
        and AUTOHEAL_COMMIT_MESSAGE_RE.fullmatch(first_line) is not None
    )


def _prune_orphan_repair_refs(api: GitHubApi, pulls: list[dict[str, Any]]) -> int:
    open_heads = {
        str((row.get("head") or {}).get("ref"))
        for row in pulls
        if isinstance((row.get("head") or {}).get("ref"), str)
    }
    prefix = f"refs/heads/{BRANCH_PREFIX}"
    refs = api.list_all(f"/git/matching-refs/heads/{BRANCH_PREFIX}", max_pages=4)
    pruned = 0
    for row in refs:
        ref = row.get("ref")
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise AutohealError("GitHub returned a ref outside CodeQL auto-heal namespace")
        branch = ref.removeprefix("refs/heads/")
        if branch in open_heads:
            continue
        obj = row.get("object") or {}
        if obj.get("type") != "commit":
            raise PolicyBlock("orphan CodeQL auto-heal ref does not point to a commit")
        head_sha = _require_sha(obj.get("sha"), "orphan CodeQL auto-heal SHA")
        commit = api.get(f"/commits/{head_sha}")
        if not _owned_generated_repair_commit(commit, head_sha):
            raise PolicyBlock("orphan CodeQL auto-heal ref lacks exact GitHub Actions ownership")
        encoded_branch = urllib.parse.quote(branch, safe="")
        api.delete(f"/git/refs/heads/{encoded_branch}")
        try:
            api.get(f"/git/ref/heads/{encoded_branch}")
        except AutohealError as exc:
            if "HTTP 404" not in str(exc):
                raise
        else:
            raise AutohealError("orphan CodeQL auto-heal ref still exists after deletion")
        pruned += 1
        print(
            json.dumps(
                {"branch": branch, "headSha": head_sha, "decision": "orphan-ref-pruned"},
                sort_keys=True,
            )
        )
    return pruned


def _generated_repairs(pulls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        pr
        for pr in pulls
        if (pr.get("user") or {}).get("login") == GITHUB_ACTIONS_LOGIN
        and (pr.get("user") or {}).get("id") == GITHUB_ACTIONS_USER_ID
        and isinstance(((pr.get("head") or {}).get("ref")), str)
        and str((pr.get("head") or {}).get("ref")).startswith(BRANCH_PREFIX)
        and _parse_marker(pr.get("body")) is not None
    ]


def _attempt_count(api: GitHubApi, alert_number: int) -> int:
    rows = api.list_all("/pulls?state=closed&sort=updated&direction=desc", max_pages=2)
    count = 0
    for pr in rows:
        if (pr.get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN:
            continue
        if (pr.get("user") or {}).get("id") != GITHUB_ACTIONS_USER_ID:
            continue
        branch = str((pr.get("head") or {}).get("ref") or "")
        if not branch.startswith(BRANCH_PREFIX):
            continue
        metadata = _parse_marker(pr.get("body"))
        if metadata is not None and metadata.get("alert") == alert_number:
            count += 1
    return count


def _create_repair(
    api: GitHubApi, subject: dict[str, Any], config: dict[str, Any], *, attempt: int
) -> int:
    branch = _branch_name(subject)
    deterministic_content = _deterministic_repair(subject)
    deterministic_only = _is_deterministic_only(subject["path"], config)
    deterministic = deterministic_content is not None
    if deterministic_only and deterministic_content is None:
        raise PolicyBlock("protected verifier alert has no code-owned deterministic repair recipe")

    if deterministic:
        _create_branch(api, branch, subject["baseSha"])
        head_sha = _commit_deterministic_repair(
            api,
            branch,
            subject["baseSha"],
            subject["path"],
            deterministic_content,
            subject["number"],
        )
    else:
        if not _model_path_allowed(subject["path"], config):
            raise PolicyBlock("alert path is outside model-autofix authority")
        _ensure_copilot_autofix(api, subject["number"])
        head_sha = _commit_copilot_autofix(api, subject["number"], branch, subject["baseSha"])

    files = _changed_files(api, subject["baseSha"], head_sha)
    _validate_candidate_diff(files, subject, config, deterministic=deterministic)
    pr_number = _create_pull_request(
        api,
        branch,
        head_sha,
        subject,
        attempt,
        deterministic=deterministic,
    )
    # Bind the branch name into the marker after creation only through the immutable branch
    # convention. The live validator derives it from the PR head and accepts an absent marker key.
    _dispatch_qualification(api, branch, head_sha)
    print(
        json.dumps(
            {
                "alert": subject["number"],
                "decision": "repair-created",
                "pr": pr_number,
                "generator": "deterministic" if deterministic else "github-codeql-autofix",
            },
            sort_keys=True,
        )
    )
    return pr_number


def reconcile(config: dict[str, Any], *, allow_merge: bool) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise AutohealError("workflow repository does not match security auto-heal config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    if not config["enabled"]:
        print("security auto-heal disabled")
        return 0

    main_sha = _current_main(api, config)
    pulls = _open_pulls(api)
    _prune_orphan_repair_refs(api, pulls)
    repairs = _generated_repairs(pulls)
    active_alerts: set[int] = set()

    for summary in repairs:
        number = summary.get("number")
        if not isinstance(number, int):
            continue
        metadata = _parse_marker(summary.get("body")) or {}
        alert_number = metadata.get("alert")
        if isinstance(alert_number, int):
            active_alerts.add(alert_number)
        try:
            live_pr = api.get(f"/pulls/{number}")
            validated_metadata, live = _validate_generated_pr(api, live_pr, config)
            _require_green_checks(api, live["headSha"], config)
            _verify_codeql_remediation(api, validated_metadata, config)
            if allow_merge and config["automergeEnabled"]:
                _post_trusted_status(api, number, validated_metadata, live, config)
                _merge(api, number, validated_metadata, live, config)
                print(json.dumps({"pr": number, "decision": "repair-merged"}, sort_keys=True))
        except PolicyBlock as exc:
            print(
                json.dumps(
                    {"pr": number, "decision": "repair-waiting", "reason": str(exc)},
                    sort_keys=True,
                )
            )

    capacity = max(0, int(config["maxOpenRepairs"]) - len(repairs))
    if capacity == 0:
        return len(repairs)

    query = urllib.parse.urlencode(
        {"state": "open", "ref": "refs/heads/main", "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    alerts = api.list_all(f"/code-scanning/alerts?{query}", max_pages=10)
    created = 0
    for alert in alerts:
        if created >= capacity:
            break
        try:
            subject = validate_alert(alert, main_sha, config)
            if subject["number"] in active_alerts:
                continue
            prior = _attempt_count(api, subject["number"])
            if prior >= config["maxAttemptsPerAlert"]:
                raise PolicyBlock("alert exhausted bounded automatic remediation attempts")
            _create_repair(api, subject, config, attempt=prior + 1)
            created += 1
            active_alerts.add(subject["number"])
        except RetryLater as exc:
            number = alert.get("number")
            print(
                json.dumps(
                    {"alert": number, "decision": "autofix-pending", "reason": str(exc)},
                    sort_keys=True,
                )
            )
        except PolicyBlock as exc:
            number = alert.get("number")
            print(
                json.dumps(
                    {"alert": number, "decision": "blocked", "reason": str(exc)},
                    sort_keys=True,
                )
            )
    return len(repairs) + created


def selftest(config: dict[str, Any]) -> None:
    owned_commit = {
        "sha": "d" * 40,
        "author": {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID},
        "commit": {
            "message": (
                "security: auto-heal CodeQL alert #7\n\n"
                "Co-authored-by: Copilot Autofix powered by AI <bot@example.invalid>"
            )
        },
    }
    if not _owned_generated_repair_commit(owned_commit, "d" * 40):
        raise AutohealError("canonical generated auto-heal commit ownership was rejected")
    for drifted in (
        {**owned_commit, "sha": "e" * 40},
        {**owned_commit, "author": {"login": "portyu9", "id": 35150859}},
        {**owned_commit, "commit": {"message": "security: unrelated maintenance"}},
    ):
        if _owned_generated_repair_commit(drifted, "d" * 40):
            raise AutohealError("non-canonical generated auto-heal ownership was accepted")

    denied = AutohealError(
        "GitHub API POST /pulls failed HTTP 403: "
        '{"message":"GitHub Actions is not permitted to create or approve pull requests."}'
    )
    if not _github_actions_pr_creation_denied(denied):
        raise AutohealError("GitHub Actions PR creation denial was not classified")
    if _github_actions_pr_creation_denied(AutohealError("HTTP 403: unrelated policy")):
        raise AutohealError("unrelated HTTP 403 was misclassified as PR creation denial")

    class _EmptyPaginationApi(GitHubApi):
        def __init__(self) -> None:
            pass

        def get(self, path: str) -> Any:
            if "/check-runs" in path:
                return {"check_runs": []}
            if "/actions/runs" in path:
                return {"workflow_runs": []}
            raise AutohealError(f"unexpected self-test pagination path: {path}")

    empty_api = _EmptyPaginationApi()
    if empty_api.list_all("/commits/" + "f" * 40 + "/check-runs", max_pages=2) != []:
        raise AutohealError("pagination rejected canonical empty check_runs response")
    if empty_api.list_all("/actions/runs?head_sha=" + "f" * 40, max_pages=2) != []:
        raise AutohealError("pagination rejected canonical empty workflow_runs response")

    class _RecordingDispatchApi(GitHubApi):
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, Any] | None]] = []

        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            if token is not None:
                raise AutohealError("qualification self-test received unexpected alternate token")
            self.calls.append((path, payload))
            return None

    dispatch_api = _RecordingDispatchApi()
    exact_sha = "f" * 40
    exact_branch = "automation/codeql-autoheal-7-abcdef123456"
    _dispatch_qualification(dispatch_api, exact_branch, exact_sha)
    if dispatch_api.calls != [
        (
            "/actions/workflows/ci.yml/dispatches",
            {"ref": exact_branch, "inputs": {"subject_sha": exact_sha}},
        ),
        ("/actions/workflows/codeql.yml/dispatches", {"ref": exact_branch}),
    ]:
        raise AutohealError("exact-subject qualification dispatch payload drifted")
    for bad_ref in (
        "automation/codeql-autoheal-0-abcdef123456",
        "automation/codeql-autoheal-7-nothex123456",
        "automation/codeql-autoheal-7-abcdef123456-extra",
        "feature/unreviewed",
    ):
        try:
            _dispatch_qualification(dispatch_api, bad_ref, exact_sha)
        except PolicyBlock:
            pass
        else:
            raise AutohealError(f"unreviewed qualification ref was accepted: {bad_ref}")

    errors = validate_config(config)
    if errors:
        raise AutohealError("security auto-heal config self-test failed: " + "; ".join(errors))

    marker = _marker(
        {
            "version": 1,
            "alert": 7,
            "base": "a" * 40,
            "head": "b" * 40,
            "fingerprint": "c" * 64,
        }
    )
    parsed = _parse_marker(marker)
    if parsed is None or parsed.get("alert") != 7:
        raise AutohealError("auto-heal marker round-trip failed")

    _validate_api_path(f"/compare/{'a' * 40}...{'b' * 40}")
    for unsafe_path in (
        "../outside",
        "/repos/../outside",
        "/repos/%2e%2e/outside",
        "//example.invalid/repos/portyu9/ai-qa-automation",
        "/repos\\outside",
    ):
        try:
            _validate_api_path(unsafe_path)
        except AutohealError:
            pass
        else:
            raise AutohealError(f"unsafe GitHub API path passed validation: {unsafe_path}")

    if _security_severity({"rule": {"security_severity_level": "high"}}) != 7.0:
        raise AutohealError("REST security severity level mapping self-test failed")
    if _security_severity({"rule": {"security_severity": "7.8"}}) != 7.8:
        raise AutohealError("numeric security severity compatibility self-test failed")
    try:
        _security_severity({"rule": {"security_severity_level": "warning"}})
    except PolicyBlock:
        pass
    else:
        raise AutohealError("unsupported security severity level did not fail closed")

    original_root = globals()["ROOT"]
    try:
        with tempfile.TemporaryDirectory(prefix="security-autoheal-selftest-") as temporary:
            root = Path(temporary)
            globals()["ROOT"] = root

            permission_path = root / "tests" / "example.py"
            permission_path.parent.mkdir(parents=True)
            permission_path.write_text(
                "def wrapped_open(path: object, flags: int, mode: int = 0o777) -> int:\n"
                "    return 1\n",
                encoding="utf-8",
            )
            permission = _deterministic_repair(
                {
                    "rule": "py/overly-permissive-file",
                    "path": "tests/example.py",
                    "line": 1,
                }
            )
            if permission is None or "0o600" not in permission or "0o777" in permission:
                raise AutohealError("permission repair recipe self-test failed")

            for relative, (old, new) in DETERMINISTIC_LOG_REPAIRS.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(old + "\n", encoding="utf-8")
                repaired = _deterministic_repair(
                    {
                        "rule": "py/clear-text-logging-sensitive-data",
                        "path": relative,
                        "line": 1,
                    }
                )
                if repaired is None or old in repaired or new not in repaired:
                    raise AutohealError(f"logging repair recipe self-test failed: {relative}")
    finally:
        globals()["ROOT"] = original_root

    if _model_path_allowed(".github/workflows/ci.yml", config):
        raise AutohealError("model autofix authority expanded into .github")
    if not _model_path_allowed("tests/unit/test_example.py", config):
        raise AutohealError("model autofix authority unexpectedly excludes tests")
    if not _is_deterministic_only("scripts/verify_ci_contract.py", config):
        raise AutohealError("CI verifier must remain deterministic-only repair authority")
    spoofed = {
        "user": {"login": "attacker", "id": 1},
        "head": {"ref": BRANCH_PREFIX + "7-deadbeef"},
        "body": marker,
    }
    if _generated_repairs([spoofed]):
        raise AutohealError("non-Actions PR spoofed the generated-repair namespace")
    print("security-autoheal self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fail-closed exact-subject CodeQL auto-heal")
    parser.add_argument("--validate-config", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    args = parser.parse_args()
    config = load_config()
    if args.validate_config:
        print("security-autoheal config: valid")
    if args.self_test:
        selftest(config)
    if args.reconcile:
        reconcile(config, allow_merge=args.allow_merge)
    if not (args.validate_config or args.self_test or args.reconcile):
        parser.error("choose --validate-config, --self-test, or --reconcile")


if __name__ == "__main__":
    main()
