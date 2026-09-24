#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
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

from security_alert_routing import (
    RoutingPolicyError,
    canonical_record as canonical_routing_record,
    read_json_evidence as read_routing_json_evidence,
    route_alert as route_security_alert,
)
from trusted_qualification import (
    TrustedQualificationError,
)
from trusted_qualification import (
    require_success as require_trusted_qualification_success,
)
from trusted_status import (
    EXPECTED_GATE_WORKFLOW_NAME,
    EXPECTED_GATE_WORKFLOW_PATH,
    TARGET_URL_RE,
    TRUSTED_STATUS_BOT_ID,
    TRUSTED_STATUS_BOT_LOGIN,
    TRUSTED_STATUS_CONTEXT,
    TRUSTED_STATUS_DESCRIPTION,
    TrustedStatusError,
    require_automatic_trusted_gate,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "security-autoheal.json"
API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
POST_MERGE_CI_WORKFLOW_ID = 339754724
POST_MERGE_CI_WORKFLOW = "ci.yml"
TRUSTED_PR_GATE_WORKFLOW_ID = 346203190
POST_MERGE_CI_PATH = ".github/workflows/ci.yml"
POST_MERGE_CI_NAME = "CI — ƳƤ AI QA Automation Framework"
POST_MERGE_CI_EVENTS = {"push", "workflow_dispatch"}
POST_MERGE_CI_REGISTRATION_ATTEMPTS = 15
POST_MERGE_CI_REGISTRATION_DELAY_SECONDS = 2
MAIN_CODEQL_WORKFLOW = "codeql.yml"
MAIN_CODEQL_WORKFLOW_ID = 359681647
MAIN_CODEQL_PATH = ".github/workflows/codeql.yml"
MAIN_CODEQL_NAME = "CodeQL"
MAIN_CODEQL_EVENTS = {"push", "workflow_dispatch", "schedule"}
MAIN_CODEQL_REGISTRATION_ATTEMPTS = 15
MAIN_CODEQL_REGISTRATION_DELAY_SECONDS = 2
TRANSIENT_GET_ATTEMPTS = 3
TRANSIENT_GET_DELAY_SECONDS = 1
GITHUB_ACTIONS_LOGIN = "github-actions[bot]"
GITHUB_ACTIONS_USER_ID = 41898282
GITHUB_ACTIONS_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
GITHUB_WEB_FLOW_LOGIN = "web-flow"
GITHUB_WEB_FLOW_USER_ID = 19864447
GITHUB_COMMITTER_NAME = "GitHub"
GITHUB_COMMITTER_EMAIL = "noreply@github.com"
SECURITY_AUTOHEAL_WORKFLOW_ID = 359898109
SECURITY_AUTOHEAL_WORKFLOW_PATH = ".github/workflows/security-autoheal.yml"
SECURITY_AUTOHEAL_RECONCILE_EVENTS = {"workflow_run", "schedule", "workflow_dispatch"}
ROUTE_PLAN_SCHEMA_VERSION = 1
ROUTE_PLAN_MAX_BYTES = 2 * 1024 * 1024
ROUTE_PLAN_ARTIFACT_PREFIX = "security-autoheal-route-plan"
ROUTE_ARTIFACT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MARKER_PREFIX = "<!-- aiqa-codeql-autoheal:"
MARKER_SUFFIX = " -->"
BRANCH_PREFIX = "automation/codeql-autoheal-"
AUTOHEAL_BRANCH_RE = re.compile(
    r"^automation/codeql-autoheal-[1-9][0-9]*-(?:[0-9a-f]{12}|[0-9a-f]{64}-a[1-9][0-9]*)$"
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
MODEL_AUTOFIX_STRATEGY = "github-codeql-autofix-v1"
OVERLY_PERMISSIVE_TEST_STRATEGY = "deterministic-overly-permissive-test-file-v1"
CLEAR_TEXT_LOG_STRATEGY = "deterministic-clear-text-log-v1"
REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY = "deterministic-reference-sut-reflective-xss-v1"
STALE_SUPERSESSION_REASON = "main-advanced"
STALE_SUPERSESSION_COMMENT_PREFIX = "<!-- aiqa-codeql-autoheal-supersession:"
STALE_SUPERSESSION_COMMENT_SUFFIX = " -->"
TERMINAL_CLOSURE_COMMENT_PREFIX = "<!-- aiqa-codeql-autoheal-terminal:"
TERMINAL_CLOSURE_COMMENT_SUFFIX = " -->"
TERMINAL_TRUSTED_GATE_EVENTS = {"schedule"}
TERMINAL_MAIN_EVENTS = {"push"}
TERMINAL_AUTOHEAL_EVENTS = {"workflow_run", "schedule"}
LEGACY_STALE_CLOSURE_CUTOFF = "2026-09-23T00:11:00Z"
LEGACY_STALE_SUPERSESSIONS = {
    207: {
        "base": "".join(("ba3d5966", "6bf19d97", "c69d681a", "0ed9d6f0", "7eef0b72")),
        "head": "".join(("58ce657d", "fe8bf21b", "c1937acc", "cbc57313", "e1f0c849")),
        "fingerprint": "".join(
            (
                "128d8316",
                "70569fcf",
                "39e14ad8",
                "9263c75c",
                "413f6d32",
                "42f1de90",
                "b9ad9b3f",
                "71a1f9cb",
            )
        ),
        "closedAt": "2026-09-22T23:36:05Z",
    },
    216: {
        "base": "".join(("b06657a6", "3018838d", "590b35ab", "b7648067", "f10c42d5")),
        "head": "".join(("e828bdee", "a0e75d4d", "aa81bfcb", "09b4dbb0", "3b487af5")),
        "fingerprint": "".join(
            (
                "d6bf8a89",
                "1cfe1985",
                "5b9d3482",
                "c8f7bb4c",
                "93eea0f6",
                "95da0917",
                "b9c0a668",
                "d31d2417",
            )
        ),
        "closedAt": "2026-09-23T00:10:26Z",
    },
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
        attempts = TRANSIENT_GET_ATTEMPTS if method == "GET" else 1
        for attempt in range(attempts):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status = int(response.status)
                    raw = response.read(max_bytes + 1)
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read(4096).decode("utf-8", errors="replace")
                if method == "GET" and exc.code in {502, 503, 504} and attempt + 1 < attempts:
                    time.sleep(TRANSIENT_GET_DELAY_SECONDS)
                    continue
                raise AutohealError(
                    f"GitHub API {method} {path} failed HTTP {exc.code}: {detail[:1000]}"
                ) from exc
            except urllib.error.URLError as exc:
                if method == "GET" and attempt + 1 < attempts:
                    time.sleep(TRANSIENT_GET_DELAY_SECONDS)
                    continue
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


def _with_stale_supersession_marker(
    body: Any,
    metadata: dict[str, Any],
    main_sha: str,
) -> str:
    base_sha = _require_sha(metadata.get("base"), "stale repair marker base SHA")
    main_sha = _require_sha(main_sha, "stale repair superseding main SHA")
    if base_sha == main_sha:
        raise PolicyBlock("stale repair supersession main must differ from marker base")
    if (
        metadata.get("supersessionReason") is not None
        or metadata.get("supersededByMain") is not None
    ):
        raise PolicyBlock("stale repair marker already carries supersession metadata")
    canonical = _marker(metadata)
    if not isinstance(body, str) or body.count(canonical) != 1:
        raise PolicyBlock("stale repair body marker is not canonical and unique")
    updated = dict(metadata)
    updated["supersessionReason"] = STALE_SUPERSESSION_REASON
    updated["supersededByMain"] = main_sha
    return body.replace(canonical, _marker(updated), 1)


def _stale_supersession_certificate(
    metadata: dict[str, Any],
    number: int,
    main_sha: str,
    *,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> dict[str, Any]:
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise PolicyBlock("stale repair PR number is invalid")
    for value, label in (
        (workflow_run_id, "stale repair workflow run id"),
        (workflow_run_attempt, "stale repair workflow run attempt"),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PolicyBlock(f"{label} is invalid")
    alert = metadata.get("alert")
    if not isinstance(alert, int) or isinstance(alert, bool) or alert < 1:
        raise PolicyBlock("stale repair marker alert number is invalid")
    fingerprint = metadata.get("fingerprint")
    if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise PolicyBlock("stale repair marker fingerprint is invalid")
    strategy = _marker_strategy(metadata)
    if not isinstance(strategy, str) or not strategy:
        raise PolicyBlock("stale repair marker strategy is invalid")
    base_sha = _require_sha(metadata.get("base"), "stale repair marker base SHA")
    head_sha = _require_sha(metadata.get("head"), "stale repair marker head SHA")
    main_sha = _require_sha(main_sha, "stale repair superseding main SHA")
    if main_sha == base_sha:
        raise PolicyBlock("stale repair supersession main must differ from marker base")
    return {
        "version": 1,
        "pr": number,
        "alert": alert,
        "base": base_sha,
        "head": head_sha,
        "fingerprint": fingerprint,
        "strategy": strategy,
        "supersessionReason": STALE_SUPERSESSION_REASON,
        "supersededByMain": main_sha,
        "workflowId": SECURITY_AUTOHEAL_WORKFLOW_ID,
        "workflowRunId": workflow_run_id,
        "workflowRunAttempt": workflow_run_attempt,
    }


def _stale_supersession_comment(certificate: dict[str, Any]) -> str:
    return (
        STALE_SUPERSESSION_COMMENT_PREFIX
        + json.dumps(certificate, separators=(",", ":"), sort_keys=True)
        + STALE_SUPERSESSION_COMMENT_SUFFIX
    )


def _parse_stale_supersession_comment(body: Any) -> dict[str, Any] | None:
    if (
        not isinstance(body, str)
        or not body.startswith(STALE_SUPERSESSION_COMMENT_PREFIX)
        or not body.endswith(STALE_SUPERSESSION_COMMENT_SUFFIX)
    ):
        return None
    raw = body[len(STALE_SUPERSESSION_COMMENT_PREFIX) : -len(STALE_SUPERSESSION_COMMENT_SUFFIX)]
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _certificate_superseding_main(
    certificate: dict[str, Any],
    metadata: dict[str, Any],
    number: int,
) -> str | None:
    try:
        expected_base = _require_sha(metadata.get("base"), "certificate marker base SHA")
        expected_head = _require_sha(metadata.get("head"), "certificate marker head SHA")
        certificate_base = _require_sha(certificate.get("base"), "certificate base SHA")
        certificate_head = _require_sha(certificate.get("head"), "certificate head SHA")
        superseding_main = _require_sha(
            certificate.get("supersededByMain"),
            "certificate superseding main SHA",
        )
    except PolicyBlock:
        return None
    if (
        certificate.get("version") != 1
        or certificate.get("pr") != number
        or certificate.get("alert") != metadata.get("alert")
        or certificate.get("fingerprint") != metadata.get("fingerprint")
        or certificate.get("strategy") != _marker_strategy(metadata)
        or certificate.get("supersessionReason") != STALE_SUPERSESSION_REASON
        or certificate.get("workflowId") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or not isinstance(certificate.get("workflowRunId"), int)
        or isinstance(certificate.get("workflowRunId"), bool)
        or certificate.get("workflowRunId") < 1
        or not isinstance(certificate.get("workflowRunAttempt"), int)
        or isinstance(certificate.get("workflowRunAttempt"), bool)
        or certificate.get("workflowRunAttempt") < 1
        or certificate_base != expected_base
        or certificate_head != expected_head
        or superseding_main == expected_base
    ):
        return None
    return superseding_main


def _current_positive_int_env(name: str) -> int:
    raw = os.environ.get(name)
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit():
        raise PolicyBlock(f"{name} is required as a positive integer")
    value = int(raw)
    if value < 1:
        raise PolicyBlock(f"{name} is required as a positive integer")
    return value


def _autoheal_workflow_run_matches(
    api: GitHubApi,
    certificate: dict[str, Any],
) -> bool:
    run_id = certificate.get("workflowRunId")
    run_attempt = certificate.get("workflowRunAttempt")
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id < 1
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
    ):
        return False
    run = api.get(f"/actions/runs/{run_id}")
    if not isinstance(run, dict):
        return False
    if (
        run.get("id") != run_id
        or run.get("workflow_id") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or run.get("path") != SECURITY_AUTOHEAL_WORKFLOW_PATH
        or run.get("run_attempt") != run_attempt
        or run.get("event") not in SECURITY_AUTOHEAL_RECONCILE_EVENTS
        or run.get("head_branch") != "main"
    ):
        return False
    if run.get("status") == "completed":
        return run.get("conclusion") == "success"
    try:
        current_run_id = _current_positive_int_env("GITHUB_RUN_ID")
        current_attempt = _current_positive_int_env("GITHUB_RUN_ATTEMPT")
    except PolicyBlock:
        return False
    return (
        run.get("status") in {"queued", "in_progress"}
        and run_id == current_run_id
        and run_attempt == current_attempt
    )


def _exact_unedited_autoheal_certificate(
    row: dict[str, Any],
    metadata: dict[str, Any],
    number: int,
) -> tuple[dict[str, Any], str] | None:
    certificate = _parse_stale_supersession_comment(row.get("body"))
    if certificate is None:
        return None
    actor = row.get("user") or {}
    if actor.get("login") != GITHUB_ACTIONS_LOGIN or actor.get("id") != GITHUB_ACTIONS_USER_ID:
        return None
    superseding_main = _certificate_superseding_main(certificate, metadata, number)
    if superseding_main is None:
        raise PolicyBlock("GitHub Actions stale-supersession certificate is malformed or drifted")
    created_at = row.get("created_at")
    if (
        not isinstance(created_at, str)
        or row.get("updated_at") != created_at
        or not _github_timestamp_at_or_before(created_at, created_at)
    ):
        raise PolicyBlock("GitHub Actions stale-supersession certificate is edited or malformed")
    return certificate, superseding_main


def _ensure_stale_supersession_certificate(
    api: GitHubApi,
    number: int,
    metadata: dict[str, Any],
    main_sha: str,
) -> dict[str, Any]:
    main_sha = _require_sha(main_sha, "stale repair superseding main SHA")
    comments = api.list_all(f"/issues/{number}/comments", max_pages=2)
    matching: list[tuple[dict[str, Any], str]] = []
    invalid_matching = 0
    for row in comments:
        parsed = _exact_unedited_autoheal_certificate(row, metadata, number)
        if parsed is None or parsed[1] != main_sha:
            continue
        if _autoheal_workflow_run_matches(api, parsed[0]):
            matching.append(parsed)
        else:
            invalid_matching += 1
    if invalid_matching:
        raise PolicyBlock(
            "stale repair has current-main supersession certificate without exact workflow authority"
        )
    if len(matching) > 1:
        raise PolicyBlock(
            "stale repair has ambiguous GitHub Actions supersession certificates for current main"
        )
    if matching:
        return matching[0][0]

    certificate = _stale_supersession_certificate(
        metadata,
        number,
        main_sha,
        workflow_run_id=_current_positive_int_env("GITHUB_RUN_ID"),
        workflow_run_attempt=_current_positive_int_env("GITHUB_RUN_ATTEMPT"),
    )
    body = _stale_supersession_comment(certificate)
    created = api.post(f"/issues/{number}/comments", {"body": body})
    if not isinstance(created, dict) or created.get("body") != body:
        raise AutohealError("GitHub did not acknowledge exact stale-supersession certificate")
    parsed = _exact_unedited_autoheal_certificate(created, metadata, number)
    if (
        parsed is None
        or parsed[0] != certificate
        or not _autoheal_workflow_run_matches(api, certificate)
    ):
        raise AutohealError("GitHub returned invalid stale-supersession certificate authority")
    return certificate


def _branch_name(subject: dict[str, Any], attempt: int | None = None) -> str:
    legacy = f"{BRANCH_PREFIX}{subject['number']}-{subject['fingerprint'][:12]}"
    if attempt is None:
        return legacy
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise AutohealError("auto-heal attempt must be a positive integer")
    fingerprint = subject.get("fingerprint")
    if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise AutohealError("auto-heal subject fingerprint is not canonical SHA-256")
    return f"{BRANCH_PREFIX}{subject['number']}-{fingerprint}-a{attempt}"


def _require_repair_branch_binding(
    branch: str,
    metadata: dict[str, Any],
    subject: dict[str, Any],
) -> None:
    attempt = metadata.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise PolicyBlock("generated repair marker attempt is invalid for branch binding")
    allowed = {
        _branch_name(subject),
        _branch_name(subject, attempt),
    }
    if branch not in allowed:
        raise PolicyBlock(
            "generated repair branch does not match the exact alert fingerprint and attempt"
        )


def _recoverable_model_autofix_branches(
    alerts: list[dict[str, Any]],
    main_sha: str,
    config: dict[str, Any],
) -> set[str]:
    branches: set[str] = set()
    max_attempts = int(config["maxAttemptsPerAlert"])
    for alert in alerts:
        try:
            provisional = route_security_alert(
                alert,
                main_sha=main_sha,
                config=config,
                autofix_eligibility="unknown",
            )
            subject = _subject_from_route(provisional)
        except (RoutingPolicyError, PolicyBlock):
            continue
        if provisional.get("strategy") != MODEL_AUTOFIX_STRATEGY:
            continue
        if provisional.get("protected") is True:
            continue
        if not _model_path_allowed(subject["path"], config):
            continue
        branches.update(_branch_name(subject, attempt) for attempt in range(1, max_attempts + 1))
    return branches


def _is_deterministic_only(path: str, config: dict[str, Any]) -> bool:
    return any(_path_matches(path, value) for value in config["deterministicOnlyPaths"])


def _model_path_allowed(path: str, config: dict[str, Any]) -> bool:
    return any(path.startswith(prefix) for prefix in config["modelAutofixPathPrefixes"])


def _deterministic_strategy(rule: Any, path: Any) -> str | None:
    if rule == "py/overly-permissive-file" and isinstance(path, str) and path.startswith("tests/"):
        return OVERLY_PERMISSIVE_TEST_STRATEGY
    if rule == "py/clear-text-logging-sensitive-data" and path in DETERMINISTIC_LOG_REPAIRS:
        return CLEAR_TEXT_LOG_STRATEGY
    if rule == "py/reflective-xss" and path == "examples/reference_sut/app.py":
        return REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    return None


def _repair_strategy(subject: dict[str, Any]) -> str:
    return (
        _deterministic_strategy(subject.get("rule"), subject.get("path")) or MODEL_AUTOFIX_STRATEGY
    )


def _marker_strategy(metadata: dict[str, Any]) -> str | None:
    explicit = metadata.get("strategy")
    if explicit is not None:
        return explicit if isinstance(explicit, str) and explicit else None
    generator = metadata.get("generator")
    if generator == "github-codeql-autofix":
        return MODEL_AUTOFIX_STRATEGY
    if generator == "deterministic":
        return _deterministic_strategy(metadata.get("rule"), metadata.get("path"))
    return None


def _require_strategy_binding(metadata: dict[str, Any], subject: dict[str, Any]) -> str:
    expected = _repair_strategy(subject)
    observed = _marker_strategy(metadata)
    if observed != expected:
        raise PolicyBlock("generated repair strategy drifted from the code-owned live strategy")
    expected_generator = (
        "github-codeql-autofix" if expected == MODEL_AUTOFIX_STRATEGY else "deterministic"
    )
    if metadata.get("generator") != expected_generator:
        raise PolicyBlock("generated repair generator does not match the code-owned strategy")
    return expected


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

    if (
        subject["rule"] == "py/reflective-xss"
        and subject["path"] == "examples/reference_sut/app.py"
    ):
        json_import = "import json\n"
        validation = """    allowed_modes = {
        "pass",
        "app-defect",
        "outdated-locator",
        "api-failure",
        "timing",
        "invalid-data",
        "prompt-injection",
    }
    if mode not in allowed_modes:
        raise HTTPException(status_code=400, detail="Invalid mode")
    safe_mode = mode
"""
        literal_binding = """    if mode == "pass":
        safe_mode: Mode = "pass"
        mode_js = '"pass"'
    elif mode == "app-defect":
        safe_mode = "app-defect"
        mode_js = '"app-defect"'
    elif mode == "outdated-locator":
        safe_mode = "outdated-locator"
        mode_js = '"outdated-locator"'
    elif mode == "api-failure":
        safe_mode = "api-failure"
        mode_js = '"api-failure"'
    elif mode == "timing":
        safe_mode = "timing"
        mode_js = '"timing"'
    elif mode == "invalid-data":
        safe_mode = "invalid-data"
        mode_js = '"invalid-data"'
    elif mode == "prompt-injection":
        safe_mode = "prompt-injection"
        mode_js = '"prompt-injection"'
    else:
        raise HTTPException(status_code=400, detail="Invalid mode")
"""
        mode_dump = "    mode_js = json.dumps(safe_mode)\n"
        if (
            text.count(json_import) != 1
            or text.count(validation) != 1
            or text.count(mode_dump) != 1
        ):
            return None
        return (
            text.replace(json_import, "", 1)
            .replace(validation, literal_binding, 1)
            .replace(mode_dump, "", 1)
        )

    return None


def _git_commit(api: GitHubApi, sha: str) -> dict[str, Any]:
    payload = api.get(f"/git/commits/{sha}")
    if not isinstance(payload, dict):
        raise AutohealError("GitHub returned invalid commit metadata")
    return payload


def _branch_head(api: GitHubApi, branch: str) -> str | None:
    encoded = urllib.parse.quote(branch, safe="")
    try:
        existing = api.get(f"/git/ref/heads/{encoded}")
    except AutohealError as exc:
        if "HTTP 404" in str(exc):
            return None
        raise
    return _require_sha(((existing or {}).get("object") or {}).get("sha"), "existing branch SHA")


def _create_branch(api: GitHubApi, branch: str, base_sha: str) -> None:
    encoded = urllib.parse.quote(branch, safe="")
    observed = _branch_head(api, branch)
    if observed is not None:
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


def _require_exact_copilot_autofix_commit(
    api: GitHubApi,
    alert_number: int,
    head_sha: str,
    base_sha: str,
) -> str:
    head_sha = _require_sha(head_sha, "Copilot Autofix commit SHA")
    commit = _git_commit(api, head_sha)
    parents = commit.get("parents")
    if not isinstance(parents, list) or len(parents) != 1:
        raise PolicyBlock("Copilot Autofix commit must have exactly one parent")
    if _require_sha((parents[0] or {}).get("sha"), "Copilot Autofix parent SHA") != base_sha:
        raise PolicyBlock("Copilot Autofix commit is not parented to exact current main")
    repository_commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_repair_commit(repository_commit, head_sha):
        raise PolicyBlock("Copilot Autofix commit lacks exact GitHub Actions ownership")
    author = (repository_commit or {}).get("author") or {}
    committer = (repository_commit or {}).get("committer") or {}
    commit = (repository_commit or {}).get("commit") or {}
    git_author = commit.get("author") or {}
    git_committer = commit.get("committer") or {}
    verification = commit.get("verification") or {}
    if (
        author.get("type") != "Bot"
        or committer.get("login") != GITHUB_WEB_FLOW_LOGIN
        or committer.get("id") != GITHUB_WEB_FLOW_USER_ID
        or committer.get("type") != "User"
        or git_author.get("name") != GITHUB_ACTIONS_LOGIN
        or git_author.get("email") != GITHUB_ACTIONS_EMAIL
        or git_committer.get("name") != GITHUB_COMMITTER_NAME
        or git_committer.get("email") != GITHUB_COMMITTER_EMAIL
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        raise PolicyBlock("Copilot Autofix commit lacks exact GitHub-signed provider provenance")
    message = str(commit.get("message") or "")
    if message.splitlines()[0] != f"security: auto-heal CodeQL alert #{alert_number}":
        raise PolicyBlock("Copilot Autofix commit is bound to a different alert")
    return head_sha


def _commit_copilot_autofix(api: GitHubApi, alert_number: int, branch: str, base_sha: str) -> str:
    existing_head = _branch_head(api, branch)
    if existing_head is None:
        _create_branch(api, branch, base_sha)
    elif existing_head == base_sha:
        raise PolicyBlock(
            "existing Copilot Autofix attempt branch has ambiguous provider-submission state"
        )
    else:
        recovered = _require_exact_copilot_autofix_commit(
            api,
            alert_number,
            existing_head,
            base_sha,
        )
        print(
            json.dumps(
                {
                    "alert": alert_number,
                    "branch": branch,
                    "decision": "autofix-commit-recovered",
                    "headSha": recovered,
                },
                sort_keys=True,
            )
        )
        return recovered

    payload = api.post(
        f"/code-scanning/alerts/{alert_number}/autofix/commits",
        {
            "target_ref": f"refs/heads/{branch}",
            "message": f"security: auto-heal CodeQL alert #{alert_number}",
        },
    )
    head_sha = _require_sha((payload or {}).get("sha"), "Copilot Autofix commit SHA")
    observed_head = _branch_head(api, branch)
    if observed_head != head_sha:
        raise AutohealError("Copilot Autofix branch did not advance to the returned commit")
    return _require_exact_copilot_autofix_commit(api, alert_number, head_sha, base_sha)


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
        raise PolicyBlock("generated repair branch changed before exact cleanup")
    api.delete(f"/git/refs/heads/{encoded}")


def _create_pull_request(
    api: GitHubApi,
    branch: str,
    head_sha: str,
    subject: dict[str, Any],
    attempt: int,
    *,
    deterministic: bool,
    strategy: str,
    route_record: dict[str, Any] | None = None,
    route_evidence: dict[str, Any] | None = None,
) -> int:
    if route_record is not None:
        try:
            canonical_routing_record(route_record)
        except RoutingPolicyError as exc:
            raise PolicyBlock(f"repair route record is invalid: {exc}") from exc
        if route_record.get("strategy") != strategy:
            raise PolicyBlock("repair route record strategy drifted before PR creation")
        expected_decision = (
            "ordinary-deterministic-autoheal" if deterministic else "ordinary-bounded-autofix"
        )
        if route_record.get("decision") != expected_decision:
            raise PolicyBlock("repair route record does not authorize this mutation lane")
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
        "strategy": strategy,
    }
    if route_record is not None:
        metadata.update(
            {
                "routeDecision": route_record["decision"],
                "routeAuthority": route_record["authority"],
                "routeRecordDigest": route_record["recordDigest"],
                "routingPolicyVersion": route_record["routingPolicyVersion"],
                "routeAutofixEligibility": route_record["autofixEligibility"],
                **(route_evidence or {}),
            }
        )
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
    try:
        require_trusted_qualification_success(
            api,
            head_sha,
            _current_main(api, config),
            required=tuple(config["requiredChecks"]),
        )
    except TrustedQualificationError as exc:
        raise PolicyBlock("automatic Trusted PR Gate is not yet admissible") from exc


def _repository_text(api: GitHubApi, path: str, ref: str) -> str:
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
    payload = api.get(f"/contents/{encoded_path}?ref={urllib.parse.quote(ref, safe='')}")
    if not isinstance(payload, dict) or payload.get("type") != "file":
        raise PolicyBlock(f"repair content is not one regular repository file: {path}")
    content = payload.get("content")
    if not isinstance(content, str) or payload.get("encoding") != "base64":
        raise PolicyBlock(f"repair content encoding is invalid: {path}")
    try:
        raw = base64.b64decode("".join(content.split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PolicyBlock(f"repair content base64 is invalid: {path}") from exc
    if len(raw) > 2 * 1024 * 1024:
        raise PolicyBlock(f"repair content exceeds bounded ingestion limit: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyBlock(f"repair content is not canonical UTF-8: {path}") from exc


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


def _require_marker_route_artifact(
    api: GitHubApi,
    metadata: dict[str, Any],
    base_sha: str,
) -> None:
    required = {
        "routePlanDigest",
        "routePlanRunId",
        "routePlanRunAttempt",
        "routeArtifactId",
        "routeArtifactName",
        "routeArtifactDigest",
    }
    present = {key for key in required if metadata.get(key) is not None}
    if not present:
        return
    if present != required:
        raise PolicyBlock("generated repair marker has incomplete route artifact provenance")
    plan_digest = metadata.get("routePlanDigest")
    run_id = metadata.get("routePlanRunId")
    run_attempt = metadata.get("routePlanRunAttempt")
    artifact_id = metadata.get("routeArtifactId")
    artifact_name = metadata.get("routeArtifactName")
    artifact_digest = metadata.get("routeArtifactDigest")
    if (
        not isinstance(plan_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", plan_digest) is None
        or not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id < 1
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or not isinstance(artifact_id, int)
        or isinstance(artifact_id, bool)
        or artifact_id < 1
        or not isinstance(artifact_name, str)
        or artifact_name
        != f"{ROUTE_PLAN_ARTIFACT_PREFIX}-{run_id}-{run_attempt}"
        or not isinstance(artifact_digest, str)
        or ROUTE_ARTIFACT_DIGEST_RE.fullmatch(artifact_digest) is None
    ):
        raise PolicyBlock("generated repair marker route artifact provenance is malformed")
    artifact = api.get(f"/actions/artifacts/{artifact_id}")
    workflow_run = (artifact or {}).get("workflow_run") or {}
    if (
        not isinstance(artifact, dict)
        or artifact.get("id") != artifact_id
        or artifact.get("name") != artifact_name
        or artifact.get("expired") is not False
        or artifact.get("digest") != artifact_digest
        or workflow_run.get("id") != run_id
        or workflow_run.get("head_sha") != base_sha
        or workflow_run.get("head_branch") != "main"
    ):
        raise PolicyBlock("generated repair route artifact drifted from its marker")
    run = api.get(f"/actions/runs/{run_id}")
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("workflow_id") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or run.get("path") != SECURITY_AUTOHEAL_WORKFLOW_PATH
        or run.get("run_attempt") != run_attempt
        or run.get("event") not in SECURITY_AUTOHEAL_RECONCILE_EVENTS
        or run.get("head_branch") != "main"
        or run.get("head_sha") != base_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
    ):
        raise PolicyBlock("generated repair route plan lacks successful controller-run authority")


def _rebind_repair_alert(
    api: GitHubApi,
    metadata: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    alert_number = metadata.get("alert")
    if not isinstance(alert_number, int) or isinstance(alert_number, bool) or alert_number < 1:
        raise PolicyBlock("generated repair marker alert number is invalid")
    matches = [
        alert
        for alert in _branch_alerts(api, "refs/heads/main")
        if alert.get("number") == alert_number
    ]
    if len(matches) != 1:
        raise PolicyBlock("generated repair no longer maps to exactly one open main CodeQL alert")
    attempt = metadata.get("attempt")
    if (
        not isinstance(attempt, int)
        or isinstance(attempt, bool)
        or attempt < 1
        or attempt > int(config["maxAttemptsPerAlert"])
    ):
        raise PolicyBlock("generated repair marker attempt is outside reviewed bounds")
    generator = metadata.get("generator")
    if generator not in {"deterministic", "github-codeql-autofix"}:
        raise PolicyBlock("generated repair marker generator is outside reviewed authority")

    route_digest = metadata.get("routeRecordDigest")
    if route_digest is None:
        subject = validate_alert(matches[0], live["baseSha"], config)
    else:
        strategy = metadata.get("strategy")
        eligibility = metadata.get("routeAutofixEligibility")
        if (
            not isinstance(route_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", route_digest) is None
            or not isinstance(strategy, str)
            or not strategy
            or eligibility not in {"available", "unavailable", "unknown"}
        ):
            raise PolicyBlock("generated repair marker routing provenance is malformed")
        try:
            route_record = route_security_alert(
                matches[0],
                main_sha=live["baseSha"],
                config=config,
                attempts_by_strategy={strategy: attempt - 1},
                autofix_eligibility=eligibility,
            )
            canonical_routing_record(route_record)
        except RoutingPolicyError as exc:
            raise PolicyBlock(f"generated repair route cannot be revalidated: {exc}") from exc
        expected_decision = (
            "ordinary-deterministic-autoheal"
            if generator == "deterministic"
            else "ordinary-bounded-autofix"
        )
        if (
            route_record.get("recordDigest") != route_digest
            or route_record.get("decision") != expected_decision
            or metadata.get("routeDecision") != expected_decision
            or metadata.get("routeAuthority") != route_record.get("authority")
            or metadata.get("routingPolicyVersion") != route_record.get("routingPolicyVersion")
            or route_record.get("strategy") != strategy
        ):
            raise PolicyBlock("generated repair marker drifted from deterministic routing truth")
        _require_marker_route_artifact(api, metadata, live["baseSha"])
        subject = _subject_from_route(route_record)

    expected = {
        "alert": subject["number"],
        "rule": subject["rule"],
        "severity": subject["severity"],
        "path": subject["path"],
        "base": subject["baseSha"],
        "fingerprint": subject["fingerprint"],
    }
    observed = {key: metadata.get(key) for key in expected}
    if observed != expected:
        raise PolicyBlock("generated repair marker drifted from the exact live CodeQL alert")
    _require_strategy_binding(metadata, subject)
    return subject


def assess_trusted_admission(
    api: GitHubApi,
    pr: dict[str, Any],
    config: dict[str, Any],
    *,
    require_checks: bool = True,
    verify_codeql: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    metadata, live = _validate_generated_pr(api, pr, config)
    commit = api.get(f"/commits/{live['headSha']}")
    if not _owned_generated_repair_commit(commit, live["headSha"]):
        raise PolicyBlock("generated repair head lacks exact GitHub Actions ownership")
    subject = _rebind_repair_alert(api, metadata, live, config)
    _require_repair_branch_binding(live["branch"], metadata, subject)
    if metadata.get("generator") == "deterministic":
        expected_content = _deterministic_repair(subject)
        if expected_content is None:
            raise PolicyBlock("deterministic repair no longer matches a code-owned recipe")
        observed_content = _repository_text(api, subject["path"], live["headSha"])
        if observed_content != expected_content:
            raise PolicyBlock("deterministic repair bytes differ from the code-owned recipe")
    elif _is_deterministic_only(subject["path"], config):
        raise PolicyBlock("protected verifier repair must remain deterministic")
    if require_checks:
        _require_green_checks(api, live["headSha"], config)
    if verify_codeql:
        _verify_codeql_remediation(api, metadata, config)
    return metadata, live


def _require_repair_lifecycle(
    pr: dict[str, Any],
    metadata: dict[str, Any],
    *,
    base_sha: str,
    main_sha: str,
) -> None:
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise PolicyBlock("generated repair PR is not open and non-draft")
    if base_sha != main_sha or metadata.get("base") != main_sha:
        raise PolicyBlock("generated repair is stale relative to current main")
    if pr.get("mergeable") is not True:
        raise PolicyBlock("generated repair PR is not definitively mergeable")


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
    _require_repair_lifecycle(
        pr,
        metadata,
        base_sha=base_sha,
        main_sha=main_sha,
    )
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


def _close_stale_repair(
    api: GitHubApi,
    number: int,
    branch: str,
    head_sha: str,
    main_sha: str,
) -> None:
    if AUTOHEAL_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("stale repair branch is outside reviewed authority")
    fresh = api.get(f"/pulls/{number}")
    fresh_head = (fresh or {}).get("head") or {}
    metadata = _parse_marker((fresh or {}).get("body"))
    if (
        (fresh or {}).get("state") != "open"
        or (fresh or {}).get("draft") is not False
        or ((fresh or {}).get("user") or {}).get("login") != GITHUB_ACTIONS_LOGIN
        or ((fresh or {}).get("user") or {}).get("id") != GITHUB_ACTIONS_USER_ID
        or fresh_head.get("ref") != branch
        or _require_sha(fresh_head.get("sha"), "stale repair live head SHA") != head_sha
        or metadata is None
        or metadata.get("version") != 1
        or metadata.get("head") != head_sha
    ):
        raise PolicyBlock("stale repair changed before exact cleanup")
    commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_repair_commit(commit, head_sha):
        raise PolicyBlock("stale repair head lacks exact GitHub Actions ownership")
    _ensure_stale_supersession_certificate(api, number, metadata, main_sha)
    closed_body = _with_stale_supersession_marker(fresh.get("body"), metadata, main_sha)
    closed = api.patch(f"/pulls/{number}", {"state": "closed", "body": closed_body})
    closed_metadata = _parse_marker((closed or {}).get("body"))
    if (
        not isinstance(closed, dict)
        or closed.get("state") != "closed"
        or closed_metadata is None
        or closed_metadata.get("supersessionReason") != STALE_SUPERSESSION_REASON
        or closed_metadata.get("supersededByMain") != main_sha
    ):
        raise AutohealError("GitHub did not acknowledge exact stale repair supersession")
    _delete_exact_generated_branch(api, branch, head_sha)


def _post_merge_ci_candidates(
    rows: list[dict[str, Any]],
    subject_sha: str,
    *,
    allowed_events: set[str] = POST_MERGE_CI_EVENTS,
) -> list[dict[str, Any]]:
    subject_sha = _require_sha(subject_sha, "post-merge CI subject SHA")
    candidates: list[dict[str, Any]] = []
    for row in rows:
        claims_ci_identity = (
            row.get("workflow_id") == POST_MERGE_CI_WORKFLOW_ID
            or row.get("name") == POST_MERGE_CI_NAME
            or row.get("path") == POST_MERGE_CI_PATH
        )
        if not claims_ci_identity:
            continue
        if (
            row.get("workflow_id") != POST_MERGE_CI_WORKFLOW_ID
            or row.get("name") != POST_MERGE_CI_NAME
            or row.get("path") != POST_MERGE_CI_PATH
        ):
            raise AutohealError("exact-subject CI run has mismatched workflow identity")
        if row.get("head_sha") != subject_sha:
            raise AutohealError("exact-subject CI run is bound to a different head SHA")
        if row.get("head_branch") != "main":
            raise AutohealError("exact-subject CI run is not bound to main")
        event = row.get("event")
        if event not in POST_MERGE_CI_EVENTS:
            raise AutohealError(f"exact-subject CI run has unexpected event: {event}")
        attempt = row.get("run_attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt != 1:
            raise AutohealError("exact-subject CI run_attempt must equal 1")
        run_id = row.get("id")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
            raise AutohealError("exact-subject CI run has invalid run id")
        status = row.get("status")
        conclusion = row.get("conclusion")
        if status not in {"queued", "in_progress", "completed"}:
            raise AutohealError(f"exact-subject CI run has invalid status: {status}")
        if status == "completed" and conclusion != "success":
            raise AutohealError(f"exact-subject CI run completed non-successfully: {conclusion}")
        if event in allowed_events:
            candidates.append(row)
    return candidates


def _select_post_merge_ci_run(
    rows: list[dict[str, Any]],
    subject_sha: str,
    *,
    allowed_events: set[str] = POST_MERGE_CI_EVENTS,
) -> dict[str, Any] | None:
    candidates = _post_merge_ci_candidates(
        rows,
        subject_sha,
        allowed_events=allowed_events,
    )
    if len(candidates) > 1:
        run_ids = sorted(int(row["id"]) for row in candidates)
        raise AutohealError(
            f"ambiguous exact-subject CI evidence for {subject_sha}: run ids {run_ids}"
        )
    return candidates[0] if candidates else None


def _post_merge_ci_runs(api: GitHubApi, subject_sha: str) -> list[dict[str, Any]]:
    encoded_sha = urllib.parse.quote(
        _require_sha(subject_sha, "post-merge CI subject SHA"), safe=""
    )
    return api.list_all(f"/actions/runs?head_sha={encoded_sha}", max_pages=2)


def _post_merge_ci_evidence(row: dict[str, Any], *, dispatched: bool) -> dict[str, Any]:
    return {
        "postMergeCiWorkflowId": POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": int(row["id"]),
        "postMergeCiRunAttempt": int(row["run_attempt"]),
        "postMergeCiEvent": str(row["event"]),
        "postMergeCiStatus": str(row["status"]),
        "postMergeCiDispatched": dispatched,
    }


def _ensure_post_merge_ci(
    api: GitHubApi,
    subject_sha: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    subject_sha = _require_sha(subject_sha, "post-merge CI subject SHA")
    if _current_main(api, config) != subject_sha:
        raise AutohealError("current main changed before post-merge CI registration")

    rows = _post_merge_ci_runs(api, subject_sha)
    existing = _select_post_merge_ci_run(rows, subject_sha)
    if existing is not None:
        if _current_main(api, config) != subject_sha:
            raise AutohealError("current main changed after post-merge CI evidence admission")
        return _post_merge_ci_evidence(existing, dispatched=False)

    observed_ids = {
        int(row["id"])
        for row in rows
        if isinstance(row.get("id"), int)
        and not isinstance(row.get("id"), bool)
        and int(row["id"]) > 0
    }
    api.post(
        f"/actions/workflows/{POST_MERGE_CI_WORKFLOW}/dispatches",
        {
            "ref": "main",
            "inputs": {"subject_sha": subject_sha, "subject_ref": "main"},
        },
    )

    registered: dict[str, Any] | None = None
    for attempt in range(POST_MERGE_CI_REGISTRATION_ATTEMPTS):
        candidate = _select_post_merge_ci_run(_post_merge_ci_runs(api, subject_sha), subject_sha)
        if candidate is not None and int(candidate["id"]) not in observed_ids:
            if candidate.get("event") != "workflow_dispatch":
                raise AutohealError(
                    "post-merge CI appeared through an unexpected event after explicit dispatch"
                )
            registered = candidate
            break
        if attempt + 1 < POST_MERGE_CI_REGISTRATION_ATTEMPTS:
            time.sleep(POST_MERGE_CI_REGISTRATION_DELAY_SECONDS)
    if registered is None:
        raise AutohealError(
            f"explicit CI dispatch did not register for exact current main {subject_sha}"
        )
    if _current_main(api, config) != subject_sha:
        raise AutohealError("current main changed after post-merge CI registration")
    return _post_merge_ci_evidence(registered, dispatched=True)


def _main_codeql_candidates(rows: list[dict[str, Any]], subject_sha: str) -> list[dict[str, Any]]:
    subject_sha = _require_sha(subject_sha, "current-main CodeQL subject SHA")
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if (
            row.get("name") != MAIN_CODEQL_NAME
            or row.get("path") != MAIN_CODEQL_PATH
            or row.get("head_branch") != "main"
            or row.get("head_sha") != subject_sha
            or row.get("event") not in MAIN_CODEQL_EVENTS
        ):
            continue
        attempt = row.get("run_attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise AutohealError("exact-main CodeQL run has invalid run_attempt")
        run_id = row.get("id")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
            raise AutohealError("exact-main CodeQL run has invalid run id")
        status = row.get("status")
        if status not in {"queued", "in_progress", "completed"}:
            raise AutohealError(f"exact-main CodeQL run has invalid status: {status}")
        if status == "completed" and row.get("conclusion") != "success":
            continue
        candidates.append(row)
    return candidates


def _select_main_codeql_run(rows: list[dict[str, Any]], subject_sha: str) -> dict[str, Any] | None:
    candidates = _main_codeql_candidates(rows, subject_sha)
    if not candidates:
        return None
    return max(candidates, key=lambda row: (int(row["id"]), int(row["run_attempt"])))


def _main_codeql_runs(api: GitHubApi, subject_sha: str) -> list[dict[str, Any]]:
    encoded_sha = urllib.parse.quote(
        _require_sha(subject_sha, "current-main CodeQL subject SHA"), safe=""
    )
    return api.list_all(f"/actions/runs?head_sha={encoded_sha}", max_pages=2)


def _ensure_current_main_codeql(
    api: GitHubApi,
    subject_sha: str,
    config: dict[str, Any],
) -> dict[str, Any]:
    subject_sha = _require_sha(subject_sha, "current-main CodeQL subject SHA")
    if _current_main(api, config) != subject_sha:
        raise AutohealError("current main changed before CodeQL refresh admission")

    rows = _main_codeql_runs(api, subject_sha)
    existing = _select_main_codeql_run(rows, subject_sha)
    if existing is not None:
        return {
            "codeqlRunId": int(existing["id"]),
            "codeqlRunAttempt": int(existing["run_attempt"]),
            "codeqlEvent": str(existing["event"]),
            "codeqlStatus": str(existing["status"]),
            "codeqlDispatched": False,
        }

    observed_ids = {
        int(row["id"])
        for row in rows
        if isinstance(row.get("id"), int)
        and not isinstance(row.get("id"), bool)
        and int(row["id"]) > 0
    }
    api.post(
        f"/actions/workflows/{MAIN_CODEQL_WORKFLOW}/dispatches",
        {
            "ref": "main",
            "inputs": {"subject_sha": subject_sha, "subject_ref": "main"},
        },
    )

    registered: dict[str, Any] | None = None
    for attempt in range(MAIN_CODEQL_REGISTRATION_ATTEMPTS):
        candidate = _select_main_codeql_run(_main_codeql_runs(api, subject_sha), subject_sha)
        if candidate is not None and int(candidate["id"]) not in observed_ids:
            if candidate.get("event") != "workflow_dispatch":
                raise AutohealError(
                    "current-main CodeQL refresh appeared through an unexpected event "
                    "after explicit dispatch"
                )
            registered = candidate
            break
        if attempt + 1 < MAIN_CODEQL_REGISTRATION_ATTEMPTS:
            time.sleep(MAIN_CODEQL_REGISTRATION_DELAY_SECONDS)
    if registered is None:
        raise AutohealError(
            f"explicit CodeQL dispatch did not register for exact current main {subject_sha}"
        )
    if _current_main(api, config) != subject_sha:
        raise AutohealError("current main changed after CodeQL refresh registration")
    return {
        "codeqlRunId": int(registered["id"]),
        "codeqlRunAttempt": int(registered["run_attempt"]),
        "codeqlEvent": str(registered["event"]),
        "codeqlStatus": str(registered["status"]),
        "codeqlDispatched": True,
    }


def _terminal_main_codeql_candidates(
    rows: list[dict[str, Any]], subject_sha: str
) -> list[dict[str, Any]]:
    subject_sha = _require_sha(subject_sha, "terminal CodeQL subject SHA")
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if (
            row.get("name") != MAIN_CODEQL_NAME
            or row.get("path") != MAIN_CODEQL_PATH
            or row.get("head_branch") != "main"
            or row.get("head_sha") != subject_sha
            or row.get("event") not in TERMINAL_MAIN_EVENTS
        ):
            continue
        attempt = row.get("run_attempt")
        run_id = row.get("id")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt != 1:
            raise AutohealError("terminal exact-main CodeQL run_attempt must equal 1")
        if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
            raise AutohealError("terminal exact-main CodeQL run has invalid run id")
        status = row.get("status")
        if status not in {"queued", "in_progress", "completed"}:
            raise AutohealError(f"terminal exact-main CodeQL run has invalid status: {status}")
        if status == "completed" and row.get("conclusion") != "success":
            raise AutohealError(
                "terminal exact-main CodeQL run completed non-successfully: "
                f"{row.get('conclusion')}"
            )
        candidates.append(row)
    return candidates


def _select_terminal_main_codeql_run(
    rows: list[dict[str, Any]], subject_sha: str
) -> dict[str, Any] | None:
    candidates = _terminal_main_codeql_candidates(rows, subject_sha)
    if len(candidates) > 1:
        run_ids = sorted(int(row["id"]) for row in candidates)
        raise AutohealError(
            f"ambiguous terminal exact-main CodeQL evidence for {subject_sha}: run ids {run_ids}"
        )
    return candidates[0] if candidates else None


def _terminal_closure_comment(certificate: dict[str, Any]) -> str:
    return (
        TERMINAL_CLOSURE_COMMENT_PREFIX
        + json.dumps(certificate, separators=(",", ":"), sort_keys=True)
        + TERMINAL_CLOSURE_COMMENT_SUFFIX
    )


def _parse_terminal_closure_comment(body: Any) -> dict[str, Any] | None:
    if (
        not isinstance(body, str)
        or not body.startswith(TERMINAL_CLOSURE_COMMENT_PREFIX)
        or not body.endswith(TERMINAL_CLOSURE_COMMENT_SUFFIX)
    ):
        return None
    raw = body[len(TERMINAL_CLOSURE_COMMENT_PREFIX) : -len(TERMINAL_CLOSURE_COMMENT_SUFFIX)]
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _terminal_trusted_gate_evidence(
    api: GitHubApi,
    number: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    base_sha = _require_sha(metadata.get("base"), "terminal trusted gate base SHA")
    head_sha = _require_sha(metadata.get("head"), "terminal trusted gate head SHA")
    rows = api.list_all(f"/commits/{head_sha}/statuses", max_pages=4)
    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("context") != TRUSTED_STATUS_CONTEXT:
            continue
        creator = row.get("creator") or {}
        if (
            creator.get("login") != TRUSTED_STATUS_BOT_LOGIN
            or creator.get("id") != TRUSTED_STATUS_BOT_ID
            or creator.get("type") != "Bot"
        ):
            continue
        status_id = row.get("id")
        if not isinstance(status_id, int) or isinstance(status_id, bool) or status_id < 1:
            raise AutohealError("terminal Trusted PR Gate status has invalid id")
        matches.append(row)
    if not matches:
        raise AutohealError("terminal Trusted PR Gate status is missing")
    latest = max(matches, key=lambda row: int(row["id"]))
    if latest.get("state") != "success" or latest.get("description") != TRUSTED_STATUS_DESCRIPTION:
        raise AutohealError("terminal Trusted PR Gate status is not an exact reviewed success")
    target_url = latest.get("target_url")
    if not isinstance(target_url, str):
        raise AutohealError("terminal Trusted PR Gate target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if match is None:
        raise AutohealError("terminal Trusted PR Gate target URL is not exact-subject-bound")
    if (
        int(match.group("pr")) != number
        or match.group("base") != base_sha
        or match.group("head") != head_sha
    ):
        raise AutohealError("terminal Trusted PR Gate status is bound to a stale subject")
    prospective_merge_sha = _require_sha(
        match.group("merge"), "terminal trusted gate prospective merge SHA"
    )
    prospective = api.get(f"/git/commits/{prospective_merge_sha}")
    parents = (prospective or {}).get("parents")
    if (
        not isinstance(prospective, dict)
        or prospective.get("sha") != prospective_merge_sha
        or not isinstance(parents, list)
        or len(parents) != 2
    ):
        raise AutohealError("terminal trusted gate prospective merge is malformed")
    observed_parents = [
        _require_sha((parent or {}).get("sha"), "terminal trusted gate merge parent SHA")
        for parent in parents
    ]
    if observed_parents != [base_sha, head_sha]:
        raise AutohealError("terminal trusted gate prospective merge parents drifted")
    prospective_tree = _require_sha(
        ((prospective or {}).get("tree") or {}).get("sha"),
        "terminal trusted gate prospective tree SHA",
    )
    head_commit = api.get(f"/git/commits/{head_sha}")
    head_tree = _require_sha(
        ((head_commit or {}).get("tree") or {}).get("sha"),
        "terminal trusted gate head tree SHA",
    )
    if prospective_tree != head_tree:
        raise AutohealError("terminal trusted gate prospective tree differs from repair head tree")

    run_id = int(match.group("run_id"))
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or run.get("id") != run_id
        or run.get("workflow_id") != TRUSTED_PR_GATE_WORKFLOW_ID
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") not in TERMINAL_TRUSTED_GATE_EVENTS
        or run.get("run_attempt") != 1
        or run.get("head_branch") != "main"
        or run.get("head_sha") != base_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != "portyu9/ai-qa-automation"
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != "portyu9/ai-qa-automation"
    ):
        raise AutohealError("terminal Trusted PR Gate target run is not exact-main evidence")
    return {
        "trustedStatusId": int(latest["id"]),
        "trustedGateWorkflowId": TRUSTED_PR_GATE_WORKFLOW_ID,
        "trustedGateRunId": run_id,
        "trustedGateRunAttempt": 1,
        "trustedGateEvent": str(run["event"]),
        "trustedProspectiveMergeSha": prospective_merge_sha,
    }


def _require_scheduled_security_trusted_gate(
    api: GitHubApi,
    number: int,
    metadata: dict[str, Any],
    live: dict[str, Any],
) -> dict[str, Any]:
    status = require_automatic_trusted_gate(
        api,
        number,
        live["headSha"],
        live["baseSha"],
        allowed_events=TERMINAL_TRUSTED_GATE_EVENTS,
    )
    try:
        _terminal_trusted_gate_evidence(api, number, metadata)
    except (AutohealError, PolicyBlock) as exc:
        raise TrustedStatusError(
            "automatic Trusted PR Gate is not schedule-bound security evidence"
        ) from exc
    return status


def _terminal_closure_certificate(
    metadata: dict[str, Any],
    number: int,
    merge_evidence: dict[str, Any],
    ci_run: dict[str, Any],
    codeql_run: dict[str, Any],
    trusted_gate: dict[str, Any],
    *,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> dict[str, Any]:
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise PolicyBlock("terminal repair PR number is invalid")
    alert = metadata.get("alert")
    if not isinstance(alert, int) or isinstance(alert, bool) or alert < 1:
        raise PolicyBlock("terminal repair alert number is invalid")
    fingerprint = metadata.get("fingerprint")
    if not isinstance(fingerprint, str) or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None:
        raise PolicyBlock("terminal repair fingerprint is invalid")
    rule = metadata.get("rule")
    path = metadata.get("path")
    strategy = _marker_strategy(metadata)
    if not isinstance(rule, str) or not rule:
        raise PolicyBlock("terminal repair rule is invalid")
    if not isinstance(path, str) or not path:
        raise PolicyBlock("terminal repair path is invalid")
    if not isinstance(strategy, str) or not strategy:
        raise PolicyBlock("terminal repair strategy is invalid")
    base_sha = _require_sha(metadata.get("base"), "terminal repair base SHA")
    head_sha = _require_sha(metadata.get("head"), "terminal repair head SHA")
    merge_sha = _require_sha(merge_evidence.get("mergeSha"), "terminal repair merge SHA")
    source_tree = _require_sha(
        merge_evidence.get("sourceTreeSha"), "terminal repair source tree SHA"
    )
    for value, label in (
        (workflow_run_id, "terminal workflow run id"),
        (workflow_run_attempt, "terminal workflow run attempt"),
        (ci_run.get("id"), "terminal CI run id"),
        (ci_run.get("run_attempt"), "terminal CI run attempt"),
        (codeql_run.get("id"), "terminal CodeQL run id"),
        (codeql_run.get("run_attempt"), "terminal CodeQL run attempt"),
        (trusted_gate.get("trustedStatusId"), "terminal trusted status id"),
        (trusted_gate.get("trustedGateWorkflowId"), "terminal trusted gate workflow id"),
        (trusted_gate.get("trustedGateRunId"), "terminal trusted gate run id"),
        (trusted_gate.get("trustedGateRunAttempt"), "terminal trusted gate run attempt"),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PolicyBlock(f"{label} is invalid")
    return {
        "version": 1,
        "outcome": "resolved",
        "pr": number,
        "alert": alert,
        "rule": rule,
        "path": path,
        "base": base_sha,
        "head": head_sha,
        "mergeSha": merge_sha,
        "sourceTreeSha": source_tree,
        "fingerprint": fingerprint,
        "strategy": strategy,
        "alertState": "fixed",
        "ciWorkflowId": POST_MERGE_CI_WORKFLOW_ID,
        "ciRunId": int(ci_run["id"]),
        "ciRunAttempt": int(ci_run["run_attempt"]),
        "ciEvent": str(ci_run["event"]),
        "codeqlWorkflowId": MAIN_CODEQL_WORKFLOW_ID,
        "codeqlRunId": int(codeql_run["id"]),
        "codeqlRunAttempt": int(codeql_run["run_attempt"]),
        "codeqlEvent": str(codeql_run["event"]),
        "trustedStatusId": int(trusted_gate["trustedStatusId"]),
        "trustedGateWorkflowId": int(trusted_gate["trustedGateWorkflowId"]),
        "trustedGateRunId": int(trusted_gate["trustedGateRunId"]),
        "trustedGateRunAttempt": int(trusted_gate["trustedGateRunAttempt"]),
        "trustedGateEvent": str(trusted_gate["trustedGateEvent"]),
        "trustedProspectiveMergeSha": _require_sha(
            trusted_gate.get("trustedProspectiveMergeSha"),
            "terminal trusted prospective merge SHA",
        ),
        "workflowId": SECURITY_AUTOHEAL_WORKFLOW_ID,
        "workflowRunId": workflow_run_id,
        "workflowRunAttempt": workflow_run_attempt,
    }


def _terminal_certificate_static_matches(
    certificate: dict[str, Any],
    metadata: dict[str, Any],
    number: int,
    merge_evidence: dict[str, Any],
) -> bool:
    try:
        expected_base = _require_sha(metadata.get("base"), "terminal marker base SHA")
        expected_head = _require_sha(metadata.get("head"), "terminal marker head SHA")
        expected_merge = _require_sha(merge_evidence.get("mergeSha"), "terminal expected merge SHA")
        expected_tree = _require_sha(
            merge_evidence.get("sourceTreeSha"), "terminal expected source tree SHA"
        )
        observed_base = _require_sha(certificate.get("base"), "terminal certificate base SHA")
        observed_head = _require_sha(certificate.get("head"), "terminal certificate head SHA")
        observed_merge = _require_sha(certificate.get("mergeSha"), "terminal certificate merge SHA")
        observed_tree = _require_sha(
            certificate.get("sourceTreeSha"), "terminal certificate source tree SHA"
        )
    except PolicyBlock:
        return False
    positive_int_fields = (
        "ciRunId",
        "codeqlRunId",
        "trustedStatusId",
        "trustedGateRunId",
        "workflowRunId",
    )
    return (
        certificate.get("version") == 1
        and certificate.get("outcome") == "resolved"
        and certificate.get("pr") == number
        and certificate.get("alert") == metadata.get("alert")
        and certificate.get("rule") == metadata.get("rule")
        and certificate.get("path") == metadata.get("path")
        and certificate.get("fingerprint") == metadata.get("fingerprint")
        and certificate.get("strategy") == _marker_strategy(metadata)
        and certificate.get("alertState") == "fixed"
        and observed_base == expected_base
        and observed_head == expected_head
        and observed_merge == expected_merge
        and observed_tree == expected_tree
        and certificate.get("ciWorkflowId") == POST_MERGE_CI_WORKFLOW_ID
        and certificate.get("ciEvent") in TERMINAL_MAIN_EVENTS
        and certificate.get("codeqlWorkflowId") == MAIN_CODEQL_WORKFLOW_ID
        and certificate.get("codeqlEvent") in TERMINAL_MAIN_EVENTS
        and certificate.get("trustedGateWorkflowId") == TRUSTED_PR_GATE_WORKFLOW_ID
        and certificate.get("trustedGateEvent") in TERMINAL_TRUSTED_GATE_EVENTS
        and certificate.get("ciRunAttempt") == 1
        and certificate.get("codeqlRunAttempt") == 1
        and certificate.get("trustedGateRunAttempt") == 1
        and certificate.get("workflowRunAttempt") == 1
        and isinstance(certificate.get("trustedProspectiveMergeSha"), str)
        and SHA.fullmatch(str(certificate.get("trustedProspectiveMergeSha"))) is not None
        and certificate.get("workflowId") == SECURITY_AUTOHEAL_WORKFLOW_ID
        and all(
            isinstance(certificate.get(field), int)
            and not isinstance(certificate.get(field), bool)
            and int(certificate[field]) > 0
            for field in positive_int_fields
        )
    )


def _terminal_evidence_run_matches(
    api: GitHubApi,
    *,
    run_id: int,
    run_attempt: int,
    workflow_id: int,
    workflow_path: str,
    workflow_name: str,
    subject_sha: str,
    allowed_events: set[str],
) -> bool:
    run = api.get(f"/actions/runs/{run_id}")
    return (
        isinstance(run, dict)
        and run.get("id") == run_id
        and run.get("workflow_id") == workflow_id
        and run.get("path") == workflow_path
        and run.get("name") == workflow_name
        and run_attempt == 1
        and run.get("run_attempt") == 1
        and run.get("head_branch") == "main"
        and run.get("head_sha") == subject_sha
        and run.get("event") in allowed_events
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
    )


def _terminal_autoheal_workflow_run_matches(
    api: GitHubApi,
    certificate: dict[str, Any],
) -> bool:
    run_id = certificate.get("workflowRunId")
    run_attempt = certificate.get("workflowRunAttempt")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1 or run_attempt != 1:
        return False
    try:
        merge_sha = _require_sha(
            certificate.get("mergeSha"),
            "terminal certificate merge SHA",
        )
    except PolicyBlock:
        return False
    run = api.get(f"/actions/runs/{run_id}")
    if not isinstance(run, dict):
        return False
    if (
        run.get("id") != run_id
        or run.get("workflow_id") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or run.get("path") != SECURITY_AUTOHEAL_WORKFLOW_PATH
        or run.get("run_attempt") != 1
        or run.get("event") not in TERMINAL_AUTOHEAL_EVENTS
        or run.get("head_branch") != "main"
        or run.get("head_sha") != merge_sha
    ):
        return False
    if run.get("status") == "completed":
        return run.get("conclusion") == "success"
    try:
        current_run_id = _current_positive_int_env("GITHUB_RUN_ID")
        current_attempt = _current_positive_int_env("GITHUB_RUN_ATTEMPT")
    except PolicyBlock:
        return False
    return (
        run.get("status") in {"queued", "in_progress"}
        and run_id == current_run_id
        and current_attempt == 1
    )


def _terminal_certificate_evidence_matches(
    api: GitHubApi,
    certificate: dict[str, Any],
    metadata: dict[str, Any],
    number: int,
) -> bool:
    merge_sha = _require_sha(certificate.get("mergeSha"), "terminal certificate merge SHA")
    trusted_gate = _terminal_trusted_gate_evidence(api, number, metadata)
    if (
        trusted_gate["trustedStatusId"] != certificate.get("trustedStatusId")
        or trusted_gate["trustedGateWorkflowId"] != certificate.get("trustedGateWorkflowId")
        or trusted_gate["trustedGateRunId"] != certificate.get("trustedGateRunId")
        or trusted_gate["trustedGateRunAttempt"] != certificate.get("trustedGateRunAttempt")
        or trusted_gate["trustedGateEvent"] != certificate.get("trustedGateEvent")
        or trusted_gate["trustedProspectiveMergeSha"]
        != certificate.get("trustedProspectiveMergeSha")
    ):
        return False
    return (
        _terminal_evidence_run_matches(
            api,
            run_id=int(certificate["ciRunId"]),
            run_attempt=int(certificate["ciRunAttempt"]),
            workflow_id=POST_MERGE_CI_WORKFLOW_ID,
            workflow_path=POST_MERGE_CI_PATH,
            workflow_name=POST_MERGE_CI_NAME,
            subject_sha=merge_sha,
            allowed_events=TERMINAL_MAIN_EVENTS,
        )
        and _terminal_evidence_run_matches(
            api,
            run_id=int(certificate["codeqlRunId"]),
            run_attempt=int(certificate["codeqlRunAttempt"]),
            workflow_id=MAIN_CODEQL_WORKFLOW_ID,
            workflow_path=MAIN_CODEQL_PATH,
            workflow_name=MAIN_CODEQL_NAME,
            subject_sha=merge_sha,
            allowed_events=TERMINAL_MAIN_EVENTS,
        )
        and _terminal_autoheal_workflow_run_matches(api, certificate)
    )


def _exact_unedited_terminal_certificate(
    row: dict[str, Any],
    metadata: dict[str, Any],
    number: int,
    merge_evidence: dict[str, Any],
) -> dict[str, Any] | None:
    body = row.get("body")
    certificate = _parse_terminal_closure_comment(body)
    if certificate is None:
        return None
    actor = row.get("user") or {}
    if actor.get("login") != GITHUB_ACTIONS_LOGIN or actor.get("id") != GITHUB_ACTIONS_USER_ID:
        return None
    if not _terminal_certificate_static_matches(certificate, metadata, number, merge_evidence):
        raise PolicyBlock("GitHub Actions terminal closure certificate is malformed or drifted")
    created_at = row.get("created_at")
    if (
        not isinstance(created_at, str)
        or row.get("updated_at") != created_at
        or not _github_timestamp_at_or_before(created_at, created_at)
    ):
        raise PolicyBlock("GitHub Actions terminal closure certificate is edited or malformed")
    return certificate


def _ensure_terminal_closure_certificate(
    api: GitHubApi,
    number: int,
    metadata: dict[str, Any],
    merge_evidence: dict[str, Any],
    ci_run: dict[str, Any],
    codeql_run: dict[str, Any],
    trusted_gate: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    comments = api.list_all(f"/issues/{number}/comments", max_pages=2)
    matching: list[dict[str, Any]] = []
    for row in comments:
        actor = row.get("user") or {}
        body = row.get("body")
        if (
            actor.get("login") == GITHUB_ACTIONS_LOGIN
            and actor.get("id") == GITHUB_ACTIONS_USER_ID
            and isinstance(body, str)
            and body.startswith(TERMINAL_CLOSURE_COMMENT_PREFIX)
        ):
            parsed = _exact_unedited_terminal_certificate(row, metadata, number, merge_evidence)
            if parsed is None:
                raise PolicyBlock("GitHub Actions terminal closure certificate is malformed")
            matching.append(parsed)
    if len(matching) > 1:
        raise PolicyBlock("repair has ambiguous GitHub Actions terminal closure certificates")
    if matching:
        certificate = matching[0]
        if not _terminal_certificate_evidence_matches(api, certificate, metadata, number):
            raise PolicyBlock(
                "terminal closure certificate no longer has exact successful workflow evidence"
            )
        return certificate, False

    certificate = _terminal_closure_certificate(
        metadata,
        number,
        merge_evidence,
        ci_run,
        codeql_run,
        trusted_gate,
        workflow_run_id=_current_positive_int_env("GITHUB_RUN_ID"),
        workflow_run_attempt=_current_positive_int_env("GITHUB_RUN_ATTEMPT"),
    )
    if not _terminal_certificate_evidence_matches(api, certificate, metadata, number):
        raise PolicyBlock("terminal closure evidence is not exact autonomous workflow evidence")
    body = _terminal_closure_comment(certificate)
    created = api.post(f"/issues/{number}/comments", {"body": body})
    if not isinstance(created, dict) or created.get("body") != body:
        raise AutohealError("GitHub did not acknowledge exact terminal closure certificate")
    parsed = _exact_unedited_terminal_certificate(created, metadata, number, merge_evidence)
    if parsed != certificate or not _terminal_certificate_evidence_matches(
        api, certificate, metadata, number
    ):
        raise AutohealError("GitHub returned invalid terminal closure certificate authority")
    return certificate, True


def _current_main_merged_repair(
    api: GitHubApi,
    main_sha: str,
) -> dict[str, Any] | None:
    main_sha = _require_sha(main_sha, "terminal closure main SHA")
    rows = api.list_all("/pulls?state=closed&sort=updated&direction=desc", max_pages=10)
    matches: list[dict[str, Any]] = []
    for pr in rows:
        head = pr.get("head") or {}
        if (
            pr.get("state") == "closed"
            and pr.get("merged_at") is not None
            and pr.get("merge_commit_sha") == main_sha
            and (pr.get("user") or {}).get("login") == GITHUB_ACTIONS_LOGIN
            and (pr.get("user") or {}).get("id") == GITHUB_ACTIONS_USER_ID
            and isinstance(head.get("ref"), str)
            and str(head.get("ref")).startswith(BRANCH_PREFIX)
            and _parse_marker(pr.get("body")) is not None
        ):
            matches.append(pr)
    if len(matches) > 1:
        numbers = sorted(
            int(pr["number"])
            for pr in matches
            if isinstance(pr.get("number"), int) and not isinstance(pr.get("number"), bool)
        )
        raise AutohealError(
            f"ambiguous merged auto-heal subjects for exact current main {main_sha}: {numbers}"
        )
    if not matches:
        return None
    number = matches[0].get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise AutohealError("merged auto-heal PR has invalid number")
    live = api.get(f"/pulls/{number}")
    if not isinstance(live, dict):
        raise AutohealError("merged auto-heal PR lookup returned malformed data")
    return live


def _verify_merged_repair_subject(
    api: GitHubApi,
    pr: dict[str, Any],
    main_sha: str,
    config: dict[str, Any],
) -> tuple[int, dict[str, Any], dict[str, Any]]:
    number = pr.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise PolicyBlock("merged repair PR number is invalid")
    metadata = _parse_marker(pr.get("body"))
    if metadata is None or metadata.get("version") != 1:
        raise PolicyBlock("merged repair lacks the exact auto-heal marker")
    if pr.get("state") != "closed" or pr.get("merged_at") is None or pr.get("draft") is not False:
        raise PolicyBlock("terminal repair is not a merged non-draft pull request")
    author = pr.get("user") or {}
    merged_by = pr.get("merged_by") or {}
    if (
        author.get("login") != GITHUB_ACTIONS_LOGIN
        or author.get("id") != GITHUB_ACTIONS_USER_ID
        or merged_by.get("login") != GITHUB_ACTIONS_LOGIN
        or merged_by.get("id") != GITHUB_ACTIONS_USER_ID
    ):
        raise PolicyBlock("terminal repair was not authored and merged by canonical GitHub Actions")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != config["repository"]
        or (base.get("repo") or {}).get("full_name") != config["repository"]
        or base.get("ref") != "main"
    ):
        raise PolicyBlock("terminal repair repository/base identity drifted")
    branch = head.get("ref")
    if not isinstance(branch, str) or AUTOHEAL_BRANCH_RE.fullmatch(branch) is None:
        raise PolicyBlock("terminal repair branch is outside the code-owned namespace")
    base_sha = _require_sha(base.get("sha"), "terminal repair live base SHA")
    head_sha = _require_sha(head.get("sha"), "terminal repair live head SHA")
    merge_sha = _require_sha(pr.get("merge_commit_sha"), "terminal repair live merge SHA")
    if (
        metadata.get("base") != base_sha
        or metadata.get("head") != head_sha
        or metadata.get("supersessionReason") is not None
        or metadata.get("supersededByMain") is not None
    ):
        raise PolicyBlock("terminal repair marker drifted from the merged subject")
    if merge_sha != main_sha:
        raise PolicyBlock("terminal repair merge is stale relative to exact current main")
    commit = api.get(f"/commits/{head_sha}")
    if not _owned_generated_repair_commit(commit, head_sha):
        raise PolicyBlock("terminal repair head lacks exact GitHub Actions ownership")
    merge_evidence = _finalize_post_merge_evidence(
        api,
        {"sha": merge_sha},
        {"baseSha": base_sha, "headSha": head_sha},
        config,
    )
    return number, metadata, merge_evidence


def _terminal_alert_is_fixed(
    api: GitHubApi,
    metadata: dict[str, Any],
) -> bool:
    alert_number = metadata.get("alert")
    if not isinstance(alert_number, int) or isinstance(alert_number, bool) or alert_number < 1:
        raise PolicyBlock("terminal repair alert number is invalid")
    alert = api.get(f"/code-scanning/alerts/{alert_number}")
    if not isinstance(alert, dict):
        raise AutohealError("terminal CodeQL alert lookup returned malformed data")
    if (alert.get("tool") or {}).get("name") != "CodeQL" or (alert.get("rule") or {}).get(
        "id"
    ) != metadata.get("rule"):
        raise AutohealError("terminal alert identity drifted from repair provenance")
    observed_path = ((alert.get("most_recent_instance") or {}).get("location") or {}).get("path")
    if observed_path != metadata.get("path"):
        raise AutohealError("terminal alert path is missing or drifted from repair provenance")
    state = alert.get("state")
    if state == "fixed":
        return True
    if state == "open":
        return False
    raise AutohealError(f"terminal CodeQL alert has non-fixed terminal state: {state}")


def _reconcile_terminal_closure(
    api: GitHubApi,
    main_sha: str,
    config: dict[str, Any],
) -> bool:
    merged = _current_main_merged_repair(api, main_sha)
    if merged is None:
        return False
    number, metadata, merge_evidence = _verify_merged_repair_subject(api, merged, main_sha, config)
    trusted_gate = _terminal_trusted_gate_evidence(api, number, metadata)

    ci = _select_post_merge_ci_run(
        _post_merge_ci_runs(api, main_sha),
        main_sha,
        allowed_events=TERMINAL_MAIN_EVENTS,
    )
    if ci is None:
        print(
            json.dumps(
                {
                    "pr": number,
                    "decision": "terminal-closure-waiting",
                    "reason": "exact-main automatic push CI has not registered",
                },
                sort_keys=True,
            )
        )
        return True
    if ci.get("status") != "completed":
        print(
            json.dumps(
                {
                    "pr": number,
                    "decision": "terminal-closure-waiting",
                    "reason": "exact-main CI is not completed",
                    "ciRunId": int(ci["id"]),
                    "ciRunAttempt": int(ci["run_attempt"]),
                    "ciStatus": str(ci["status"]),
                },
                sort_keys=True,
            )
        )
        return True

    codeql = _select_terminal_main_codeql_run(_main_codeql_runs(api, main_sha), main_sha)
    if codeql is None:
        print(
            json.dumps(
                {
                    "pr": number,
                    "decision": "terminal-closure-waiting",
                    "reason": "exact-main automatic CodeQL has not registered",
                },
                sort_keys=True,
            )
        )
        return True
    if codeql.get("status") != "completed":
        print(
            json.dumps(
                {
                    "pr": number,
                    "decision": "terminal-closure-waiting",
                    "reason": "exact-main CodeQL is not completed",
                    "codeqlRunId": int(codeql["id"]),
                    "codeqlRunAttempt": int(codeql["run_attempt"]),
                    "codeqlStatus": str(codeql["status"]),
                },
                sort_keys=True,
            )
        )
        return True

    if _current_main(api, config) != main_sha:
        raise AutohealError("current main changed before terminal closure certification")
    if not _terminal_alert_is_fixed(api, metadata):
        print(
            json.dumps(
                {
                    "decision": "terminal-closure-waiting",
                    "reason": "exact-main CodeQL succeeded but the alert is still open",
                },
                sort_keys=True,
            )
        )
        return True
    _, published = _ensure_terminal_closure_certificate(
        api,
        number,
        metadata,
        merge_evidence,
        ci,
        codeql,
        trusted_gate,
    )
    if _current_main(api, config) != main_sha:
        raise AutohealError("current main changed after terminal closure certification")
    print(
        json.dumps(
            {
                "decision": "repair-verified",
                "terminalCertificate": "durable-unedited-github-actions-comment",
            },
            sort_keys=True,
        )
    )
    return published


def _verify_actual_merge_commit(
    api: GitHubApi,
    result: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> tuple[str, str]:
    merge_sha = _require_sha(result.get("sha"), "actual security auto-heal merge SHA")
    commit = api.get(f"/git/commits/{merge_sha}")
    parents = (commit or {}).get("parents")
    if not isinstance(parents, list) or len(parents) != 2:
        raise AutohealError("actual security auto-heal merge commit must have exactly two parents")
    observed = [
        _require_sha((parent or {}).get("sha"), "actual security auto-heal merge parent SHA")
        for parent in parents
    ]
    expected = [live["baseSha"], live["headSha"]]
    if observed != expected:
        raise AutohealError(
            f"actual security auto-heal merge parents changed: expected {expected}, got {observed}"
        )
    merge_tree = _require_sha(
        ((commit or {}).get("tree") or {}).get("sha"), "actual security auto-heal merge tree SHA"
    )
    head_commit = api.get(f"/git/commits/{live['headSha']}")
    head_tree = _require_sha(
        ((head_commit or {}).get("tree") or {}).get("sha"),
        "validated security auto-heal head tree SHA",
    )
    if merge_tree != head_tree:
        raise AutohealError(
            "actual security auto-heal merge tree differs from the validated repair head tree"
        )
    current_main = _current_main(api, config)
    if current_main != merge_sha:
        raise AutohealError(
            f"main advanced during guarded security merge: expected {merge_sha}, got {current_main}"
        )
    return merge_sha, merge_tree


def _finalize_post_merge_evidence(
    api: GitHubApi,
    result: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    merge_sha, merge_tree = _verify_actual_merge_commit(api, result, live, config)
    ci_evidence = _ensure_post_merge_ci(api, merge_sha, config)
    return {
        "mergeSha": merge_sha,
        "sourceTreeSha": merge_tree,
        "postMergeBinding": (
            "exact-current-main-parents-validated-source-tree-and-ci-registration"
        ),
        **ci_evidence,
    }


def _merge(
    api: GitHubApi,
    pr_number: int,
    metadata: dict[str, Any],
    live: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    fresh = api.get(f"/pulls/{pr_number}")
    rebound_metadata, rebound_live = assess_trusted_admission(
        api, fresh, config, require_checks=False
    )
    if rebound_metadata != metadata or rebound_live != live:
        raise PolicyBlock("repair PR changed before guarded merge")
    _require_scheduled_security_trusted_gate(
        api,
        pr_number,
        rebound_metadata,
        rebound_live,
    )
    result = api.put(
        f"/pulls/{pr_number}/merge",
        {"sha": live["headSha"], "merge_method": config["mergeMethod"]},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        message = result.get("message") if isinstance(result, dict) else result
        raise AutohealError(f"GitHub declined security auto-heal merge: {message}")
    return _finalize_post_merge_evidence(api, result, live, config)


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


def _prune_orphan_repair_refs(
    api: GitHubApi,
    pulls: list[dict[str, Any]],
    *,
    preserve_branches: set[str] | None = None,
) -> int:
    preserved = preserve_branches or set()
    if any(AUTOHEAL_BRANCH_RE.fullmatch(branch) is None for branch in preserved):
        raise AutohealError("orphan-ref preservation contains an invalid auto-heal branch")
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
        if branch in open_heads or branch in preserved:
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


def _github_timestamp_at_or_before(value: Any, cutoff: Any) -> bool:
    if not isinstance(value, str) or not isinstance(cutoff, str):
        return False
    try:
        observed = time.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        boundary = time.strptime(cutoff, "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return False
    return observed <= boundary


def _closure_transitions(api: GitHubApi, number: int) -> list[dict[str, Any]]:
    events = api.list_all(f"/issues/{number}/events", max_pages=2)
    transitions = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event") in {"closed", "reopened"}
    ]
    transitions.sort(
        key=lambda event: (
            str(event.get("created_at") or ""),
            int(event.get("id")) if isinstance(event.get("id"), int) else 0,
        )
    )
    return transitions


def _closed_by_autoheal_bot(api: GitHubApi, number: int) -> bool:
    transitions = _closure_transitions(api, number)
    if not transitions:
        return False
    final = transitions[-1]
    actor = final.get("actor") or {}
    return (
        final.get("event") == "closed"
        and actor.get("login") == GITHUB_ACTIONS_LOGIN
        and actor.get("id") == GITHUB_ACTIONS_USER_ID
    )


def _proven_stale_supersession(
    api: GitHubApi,
    pr: dict[str, Any],
    metadata: dict[str, Any],
    current_main_sha: str,
) -> bool:
    if pr.get("state") != "closed" or pr.get("merged_at") is not None:
        return False
    number = pr.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        return False
    try:
        marker_base = _require_sha(metadata.get("base"), "closed repair marker base SHA")
        marker_head = _require_sha(metadata.get("head"), "closed repair marker head SHA")
        live_base = _require_sha((pr.get("base") or {}).get("sha"), "closed repair base SHA")
        live_head = _require_sha((pr.get("head") or {}).get("sha"), "closed repair head SHA")
        current_main_sha = _require_sha(current_main_sha, "attempt-accounting main SHA")
    except PolicyBlock:
        return False
    if (
        metadata.get("version") != 1
        or marker_base != live_base
        or marker_head != live_head
        or marker_base == current_main_sha
    ):
        return False

    transitions = _closure_transitions(api, number)
    if not transitions:
        return False
    final = transitions[-1]
    actor = final.get("actor") or {}
    if (
        final.get("event") != "closed"
        or actor.get("login") != GITHUB_ACTIONS_LOGIN
        or actor.get("id") != GITHUB_ACTIONS_USER_ID
    ):
        return False

    reason = metadata.get("supersessionReason")
    superseded_by = metadata.get("supersededByMain")
    if reason is not None or superseded_by is not None:
        if reason != STALE_SUPERSESSION_REASON:
            return False
        try:
            superseded_by_sha = _require_sha(
                superseded_by,
                "closed repair superseding main SHA",
            )
        except PolicyBlock:
            return False
        if superseded_by_sha == marker_base:
            return False
        comments = api.list_all(f"/issues/{number}/comments", max_pages=2)
        certificates: list[tuple[dict[str, Any], str, str]] = []
        for row in comments:
            try:
                parsed = _exact_unedited_autoheal_certificate(row, metadata, number)
            except PolicyBlock:
                return False
            if parsed is None or parsed[1] != superseded_by_sha:
                continue
            created_at = row.get("created_at")
            if not isinstance(created_at, str):
                return False
            certificates.append((parsed[0], parsed[1], created_at))
        if len(certificates) != 1:
            return False
        certificate, certificate_main, certificate_created_at = certificates[0]
        if not _autoheal_workflow_run_matches(api, certificate):
            return False
        if certificate_main != superseded_by_sha:
            return False
        final_created_at = final.get("created_at")
        if not _github_timestamp_at_or_before(certificate_created_at, final_created_at):
            return False
        if len(transitions) > 1:
            previous_created_at = transitions[-2].get("created_at")
            if _github_timestamp_at_or_before(certificate_created_at, previous_created_at):
                return False
        return True

    legacy = LEGACY_STALE_SUPERSESSIONS.get(number)
    if legacy is None:
        return False
    closed_at = pr.get("closed_at")
    return (
        marker_base == legacy["base"]
        and marker_head == legacy["head"]
        and metadata.get("fingerprint") == legacy["fingerprint"]
        and closed_at == legacy["closedAt"]
        and _github_timestamp_at_or_before(
            closed_at,
            LEGACY_STALE_CLOSURE_CUTOFF,
        )
    )


def _attempt_count(
    api: GitHubApi,
    alert_number: int,
    strategy: str,
    current_main_sha: str,
) -> int:
    current_main_sha = _require_sha(current_main_sha, "attempt-accounting main SHA")
    rows = api.list_all("/pulls?state=closed&sort=updated&direction=desc", max_pages=10)
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
        if (
            metadata is not None
            and metadata.get("alert") == alert_number
            and _marker_strategy(metadata) == strategy
        ):
            if _proven_stale_supersession(api, pr, metadata, current_main_sha):
                continue
            count += 1
    return count


def _autofix_evidence(api: GitHubApi, alert_number: int) -> str:
    if not isinstance(alert_number, int) or isinstance(alert_number, bool) or alert_number < 1:
        raise AutohealError("route planning received an invalid alert number")
    status, payload = api.request_status("GET", f"/code-scanning/alerts/{alert_number}/autofix")
    state = (payload or {}).get("status") if isinstance(payload, dict) else None
    if status == 200 and state == "success":
        return "available"
    if status == 404 or (status == 200 and state in {"pending", "in_progress", "queued"}):
        return "unknown"
    return "unavailable"


def _route_record_for_alert(
    api: GitHubApi,
    alert: dict[str, Any],
    main_sha: str,
    config: dict[str, Any],
    *,
    autofix_eligibility: str | None = None,
) -> dict[str, Any]:
    number = alert.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise AutohealError("route planning received an invalid alert identity")
    try:
        provisional = route_security_alert(
            alert,
            main_sha=main_sha,
            config=config,
            autofix_eligibility=autofix_eligibility or "unknown",
        )
        strategy = provisional["strategy"]
        if not isinstance(strategy, str) or not strategy:
            raise AutohealError("routing policy produced an invalid remediation strategy")
        evidence = autofix_eligibility or "unknown"
        if (
            autofix_eligibility is None
            and strategy == MODEL_AUTOFIX_STRATEGY
            and provisional.get("decision") == "blocked-external-evidence"
        ):
            evidence = _autofix_evidence(api, number)
        attempts = _attempt_count(api, number, strategy, main_sha)
        return route_security_alert(
            alert,
            main_sha=main_sha,
            config=config,
            attempts_by_strategy={strategy: attempts},
            autofix_eligibility=evidence,
        )
    except RoutingPolicyError as exc:
        raise AutohealError(f"deterministic security routing failed closed: {exc}") from exc


def _subject_from_route(record: dict[str, Any]) -> dict[str, Any]:
    required = {
        "alertNumber": int,
        "rule": str,
        "securitySeverity": (int, float),
        "path": str,
        "line": int,
        "baseSha": str,
        "fingerprint": str,
        "strategy": str,
        "recordDigest": str,
    }
    for key, expected in required.items():
        value = record.get(key)
        if isinstance(value, bool) or not isinstance(value, expected):
            raise PolicyBlock(f"routing record field is malformed: {key}")
    return {
        "number": record["alertNumber"],
        "rule": record["rule"],
        "severity": float(record["securitySeverity"]),
        "path": record["path"],
        "line": record["line"],
        "baseSha": _require_sha(record["baseSha"], "routing record base SHA"),
        "fingerprint": record["fingerprint"],
    }


def _canonical_route_plan(plan: dict[str, Any]) -> bytes:
    raw = dict(plan)
    digest = raw.pop("planDigest", None)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise AutohealError("route plan digest is missing or malformed")
    records = raw.get("records")
    if not isinstance(records, list) or len(records) > 100:
        raise AutohealError("route plan records are malformed or exceed the bounded alert limit")
    seen: set[int] = set()
    for record in records:
        if not isinstance(record, dict):
            raise AutohealError("route plan contains a non-object routing record")
        try:
            canonical_routing_record(record)
        except RoutingPolicyError as exc:
            raise AutohealError(f"route plan contains invalid routing evidence: {exc}") from exc
        number = record.get("alertNumber")
        if not isinstance(number, int) or isinstance(number, bool) or number < 1 or number in seen:
            raise AutohealError("route plan contains an invalid or duplicate alert identity")
        seen.add(number)
    canonical = json.dumps(raw, separators=(",", ":"), sort_keys=True).encode("utf-8")
    expected = hashlib.sha256(canonical).hexdigest()
    if digest != expected:
        raise AutohealError("route plan digest does not match its canonical content")
    raw["planDigest"] = digest
    payload = (json.dumps(raw, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > ROUTE_PLAN_MAX_BYTES:
        raise AutohealError("route plan exceeds the bounded persistence limit")
    return payload


def _build_route_plan(
    api: GitHubApi,
    config: dict[str, Any],
    main_sha: str,
) -> dict[str, Any]:
    query = urllib.parse.urlencode(
        {"state": "open", "ref": "refs/heads/main", "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    alerts = api.list_all(f"/code-scanning/alerts?{query}", max_pages=10)
    if len(alerts) > 100:
        raise AutohealError("live CodeQL alert set exceeds the bounded routing limit")
    records: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            raise AutohealError("GitHub returned a non-object CodeQL alert")
        records.append(_route_record_for_alert(api, alert, main_sha, config))
    records.sort(key=lambda record: int(record["alertNumber"]))
    if _current_main(api, config) != main_sha:
        raise AutohealError("main advanced while deterministic route planning was in progress")
    plan: dict[str, Any] = {
        "schemaVersion": ROUTE_PLAN_SCHEMA_VERSION,
        "repository": config["repository"],
        "workflowId": SECURITY_AUTOHEAL_WORKFLOW_ID,
        "workflowRunId": _current_positive_int_env("GITHUB_RUN_ID"),
        "workflowRunAttempt": _current_positive_int_env("GITHUB_RUN_ATTEMPT"),
        "mainSha": main_sha,
        "records": records,
    }
    canonical = json.dumps(plan, separators=(",", ":"), sort_keys=True).encode("utf-8")
    plan["planDigest"] = hashlib.sha256(canonical).hexdigest()
    _canonical_route_plan(plan)
    return plan


def _write_route_plan(path: Path, plan: dict[str, Any]) -> None:
    payload = _canonical_route_plan(plan)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent.chmod(0o700)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise AutohealError("route plan persistence requires no-follow directory APIs")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
    except OSError as exc:
        raise AutohealError("unable to create exclusive route plan evidence") from exc
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise AutohealError("route plan persistence made no forward progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(parent, os.O_RDONLY | directory | nofollow)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def plan_routes(config: dict[str, Any], output: Path) -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise AutohealError("workflow repository does not match security auto-heal config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    main_sha = _current_main(api, config)
    plan = _build_route_plan(api, config, main_sha)
    _write_route_plan(output, plan)
    print(
        json.dumps(
            {
                "decision": "route-plan-persisted",
                "mainSha": main_sha,
                "planDigest": plan["planDigest"],
                "records": len(plan["records"]),
                "workflowRunId": plan["workflowRunId"],
                "workflowRunAttempt": plan["workflowRunAttempt"],
            },
            sort_keys=True,
        )
    )
    return plan


def _load_route_plan(path: Path, config: dict[str, Any]) -> dict[str, Any]:
    try:
        plan = read_routing_json_evidence(
            path,
            max_bytes=ROUTE_PLAN_MAX_BYTES,
            label="security auto-heal route plan",
        )
    except RoutingPolicyError as exc:
        raise AutohealError(f"unable to read route plan evidence: {exc}") from exc
    if not isinstance(plan, dict):
        raise AutohealError("security auto-heal route plan must be a JSON object")
    if set(plan) != {
        "schemaVersion",
        "repository",
        "workflowId",
        "workflowRunId",
        "workflowRunAttempt",
        "mainSha",
        "records",
        "planDigest",
    }:
        raise AutohealError("route plan keys must equal the reviewed schema")
    if (
        plan.get("schemaVersion") != ROUTE_PLAN_SCHEMA_VERSION
        or plan.get("repository") != config["repository"]
        or plan.get("workflowId") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or plan.get("workflowRunId") != _current_positive_int_env("GITHUB_RUN_ID")
        or plan.get("workflowRunAttempt") != _current_positive_int_env("GITHUB_RUN_ATTEMPT")
    ):
        raise AutohealError("route plan is not bound to the exact controller run")
    _require_sha(plan.get("mainSha"), "route plan main SHA")
    _canonical_route_plan(plan)
    return plan


def _require_route_plan_artifact(
    api: GitHubApi,
    plan: dict[str, Any],
    *,
    artifact_id: int,
    artifact_name: str,
    artifact_digest: str,
) -> dict[str, Any]:
    if not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id < 1:
        raise AutohealError("route plan artifact id is invalid")
    expected_name = (
        f"{ROUTE_PLAN_ARTIFACT_PREFIX}-{plan['workflowRunId']}-{plan['workflowRunAttempt']}"
    )
    if artifact_name != expected_name:
        raise AutohealError("route plan artifact name is not bound to the exact controller run")
    if ROUTE_ARTIFACT_DIGEST_RE.fullmatch(artifact_digest) is None:
        raise AutohealError("route plan artifact digest is malformed")
    artifact = api.get(f"/actions/artifacts/{artifact_id}")
    workflow_run = (artifact or {}).get("workflow_run") or {}
    if (
        not isinstance(artifact, dict)
        or artifact.get("id") != artifact_id
        or artifact.get("name") != expected_name
        or artifact.get("expired") is not False
        or artifact.get("digest") != artifact_digest
        or not isinstance(artifact.get("size_in_bytes"), int)
        or artifact.get("size_in_bytes") <= 0
        or artifact.get("size_in_bytes") > ROUTE_PLAN_MAX_BYTES
        or workflow_run.get("id") != plan["workflowRunId"]
        or workflow_run.get("head_sha") != plan["mainSha"]
        or workflow_run.get("head_branch") != "main"
    ):
        raise AutohealError("route plan artifact metadata drifted from the exact controller run")
    run = api.get(f"/actions/runs/{plan['workflowRunId']}")
    if (
        not isinstance(run, dict)
        or run.get("id") != plan["workflowRunId"]
        or run.get("workflow_id") != SECURITY_AUTOHEAL_WORKFLOW_ID
        or run.get("path") != SECURITY_AUTOHEAL_WORKFLOW_PATH
        or run.get("run_attempt") != plan["workflowRunAttempt"]
        or run.get("event") not in SECURITY_AUTOHEAL_RECONCILE_EVENTS
        or run.get("head_branch") != "main"
        or run.get("head_sha") != plan["mainSha"]
        or run.get("status") not in {"queued", "in_progress"}
    ):
        raise AutohealError("route plan artifact lacks exact in-progress controller authority")
    return {
        "routePlanDigest": plan["planDigest"],
        "routePlanRunId": plan["workflowRunId"],
        "routePlanRunAttempt": plan["workflowRunAttempt"],
        "routeArtifactId": artifact_id,
        "routeArtifactName": artifact_name,
        "routeArtifactDigest": artifact_digest,
    }


def _rebind_route_plan(
    api: GitHubApi,
    plan: dict[str, Any],
    config: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    main_sha = _current_main(api, config)
    if main_sha != plan["mainSha"]:
        raise AutohealError("route plan is stale relative to exact current main")
    query = urllib.parse.urlencode(
        {"state": "open", "ref": "refs/heads/main", "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    alerts = api.list_all(f"/code-scanning/alerts?{query}", max_pages=10)
    planned = {int(record["alertNumber"]): record for record in plan["records"]}
    if len(planned) != len(plan["records"]):
        raise AutohealError("route plan contains duplicate alert identities")
    live_numbers: set[int] = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            raise AutohealError("GitHub returned a non-object CodeQL alert")
        number = alert.get("number")
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise AutohealError("GitHub returned an invalid CodeQL alert identity")
        live_numbers.add(number)
        expected = planned.get(number)
        if expected is None:
            raise AutohealError("live CodeQL alert is absent from persisted route evidence")
        live = _route_record_for_alert(
            api,
            alert,
            main_sha,
            config,
            autofix_eligibility=str(expected.get("autofixEligibility") or ""),
        )
        try:
            if canonical_routing_record(live) != canonical_routing_record(expected):
                raise AutohealError("live routing truth drifted from persisted route evidence")
        except RoutingPolicyError as exc:
            raise AutohealError(f"persisted route evidence is invalid: {exc}") from exc
    if set(planned) != live_numbers:
        raise AutohealError("persisted route evidence references an alert no longer open on main")
    if _current_main(api, config) != main_sha:
        raise AutohealError("main advanced while route plan was being revalidated")
    return planned


def _create_repair(
    api: GitHubApi,
    subject: dict[str, Any],
    config: dict[str, Any],
    *,
    attempt: int,
    strategy: str,
    route_record: dict[str, Any] | None = None,
    route_evidence: dict[str, Any] | None = None,
) -> int:
    if _current_main(api, config) != subject["baseSha"]:
        raise PolicyBlock("main advanced before route-authorized repair mutation")
    branch = _branch_name(subject, attempt)
    expected_strategy = _repair_strategy(subject)
    deterministic = strategy != MODEL_AUTOFIX_STRATEGY
    if route_record is None:
        if strategy != expected_strategy:
            raise PolicyBlock("repair creation strategy drifted from the code-owned live strategy")
    else:
        if strategy != expected_strategy or route_record.get("strategy") != strategy:
            raise PolicyBlock("repair creation strategy drifted from the persisted route")
        expected_decision = (
            "ordinary-deterministic-autoheal" if deterministic else "ordinary-bounded-autofix"
        )
        if route_record.get("decision") != expected_decision:
            raise PolicyBlock("persisted route does not authorize repair creation")
    deterministic_content = _deterministic_repair(subject) if deterministic else None
    deterministic_only = _is_deterministic_only(subject["path"], config)
    if deterministic and deterministic_content is None:
        raise PolicyBlock("code-owned deterministic repair strategy no longer reproduces")
    if deterministic_only and not deterministic:
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
        if route_record is None:
            _ensure_copilot_autofix(api, subject["number"])
        elif route_record.get("autofixEligibility") != "available":
            raise PolicyBlock("persisted route lacks affirmative Autofix availability")
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
        strategy=strategy,
        route_record=route_record,
        route_evidence=route_evidence,
    )
    # Bind the branch name into the marker after creation only through the immutable branch
    # convention. The live validator derives it from the PR head and accepts an absent marker key.
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


def reconcile(
    config: dict[str, Any],
    *,
    allow_merge: bool,
    route_plan_path: Path | None = None,
    route_artifact_id: int | None = None,
    route_artifact_name: str | None = None,
    route_artifact_digest: str | None = None,
) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if repository != config["repository"]:
        raise AutohealError("workflow repository does not match security auto-heal config")
    api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    if not config["enabled"]:
        print("security auto-heal disabled")
        return 0

    main_sha = _current_main(api, config)
    route_records: dict[int, dict[str, Any]] | None = None
    route_evidence: dict[str, Any] | None = None
    if route_plan_path is not None:
        if (
            route_artifact_id is None
            or route_artifact_name is None
            or route_artifact_digest is None
        ):
            raise AutohealError("route plan artifact provenance is required for live reconciliation")
        plan = _load_route_plan(route_plan_path, config)
        if plan["mainSha"] != main_sha:
            raise AutohealError("persisted route plan is stale relative to exact current main")
        route_evidence = _require_route_plan_artifact(
            api,
            plan,
            artifact_id=route_artifact_id,
            artifact_name=route_artifact_name,
            artifact_digest=route_artifact_digest,
        )
        route_records = _rebind_route_plan(api, plan, config)
    if _reconcile_terminal_closure(api, main_sha, config):
        return 0
    pulls = _open_pulls(api)
    repairs = _generated_repairs(pulls)
    active_alerts: set[int] = set()
    closed_stale = 0

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
            validated_metadata, live = assess_trusted_admission(
                api, live_pr, config, require_checks=False
            )
            if allow_merge and config["automergeEnabled"]:
                try:
                    _require_scheduled_security_trusted_gate(
                        api,
                        number,
                        validated_metadata,
                        live,
                    )
                except TrustedStatusError as exc:
                    raise PolicyBlock("automatic Trusted PR Gate is not yet admissible") from exc
                merge_evidence = _merge(api, number, validated_metadata, live, config)
                print(
                    json.dumps(
                        {
                            "pr": number,
                            "decision": "repair-merged",
                            "headSha": live["headSha"],
                            **merge_evidence,
                        },
                        sort_keys=True,
                    )
                )
                return max(0, len(repairs) - closed_stale - 1)
        except PolicyBlock as exc:
            reason = str(exc)
            print(
                json.dumps(
                    {"pr": number, "decision": "repair-waiting", "reason": reason},
                    sort_keys=True,
                )
            )
            if reason == "generated repair is stale relative to current main":
                branch = str((summary.get("head") or {}).get("ref") or "")
                stale_head_sha = _require_sha(
                    ((summary.get("head") or {}).get("sha")),
                    "stale repair summary head SHA",
                )
                _close_stale_repair(api, number, branch, stale_head_sha, main_sha)
                closed_stale += 1
                if isinstance(alert_number, int):
                    active_alerts.discard(alert_number)

    remaining_repairs = len(repairs) - closed_stale

    query = urllib.parse.urlencode(
        {"state": "open", "ref": "refs/heads/main", "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    alerts = api.list_all(f"/code-scanning/alerts?{query}", max_pages=10)
    for alert in alerts:
        instance = alert.get("most_recent_instance") or {}
        if instance.get("ref") != "refs/heads/main":
            continue
        alert_instance_sha = _require_sha(instance.get("commit_sha"), "alert instance SHA")
        if alert_instance_sha == main_sha:
            continue
        refresh = _ensure_current_main_codeql(api, main_sha, config)
        print(
            json.dumps(
                {
                    "alert": alert.get("number"),
                    "decision": (
                        "codeql-refresh-dispatched"
                        if refresh["codeqlDispatched"]
                        else "codeql-refresh-waiting"
                    ),
                    "staleSha": alert_instance_sha,
                    "currentMain": main_sha,
                    **refresh,
                },
                sort_keys=True,
            )
        )
        return remaining_repairs

    preserve_branches = _recoverable_model_autofix_branches(alerts, main_sha, config)
    _prune_orphan_repair_refs(
        api,
        pulls,
        preserve_branches=preserve_branches,
    )

    capacity = max(0, int(config["maxOpenRepairs"]) - remaining_repairs)
    if capacity == 0:
        return remaining_repairs

    created = 0
    for alert in alerts:
        if created >= capacity:
            break
        try:
            if route_records is None:
                subject = validate_alert(alert, main_sha, config)
                if subject["number"] in active_alerts:
                    continue
                strategy = _repair_strategy(subject)
                prior = _attempt_count(api, subject["number"], strategy, main_sha)
                if prior >= config["maxAttemptsPerAlert"]:
                    raise PolicyBlock(
                        "alert exhausted bounded automatic remediation attempts for current strategy"
                    )
                _create_repair(
                    api,
                    subject,
                    config,
                    attempt=prior + 1,
                    strategy=strategy,
                )
                created += 1
                active_alerts.add(subject["number"])
                continue

            number = alert.get("number")
            if not isinstance(number, int) or isinstance(number, bool) or number < 1:
                raise PolicyBlock("live alert identity is invalid after route-plan revalidation")
            record = route_records.get(number)
            if record is None:
                raise PolicyBlock("live alert lacks persisted route-plan evidence")
            if number in active_alerts:
                continue
            decision = record.get("decision")
            strategy = record.get("strategy")
            prior = record.get("strategyAttemptCount")
            if (
                not isinstance(strategy, str)
                or not strategy
                or not isinstance(prior, int)
                or isinstance(prior, bool)
                or prior < 0
            ):
                raise PolicyBlock("persisted route record strategy accounting is malformed")

            if (
                decision == "blocked-external-evidence"
                and strategy == MODEL_AUTOFIX_STRATEGY
                and record.get("autofixEligibility") == "unknown"
            ):
                subject = _subject_from_route(record)
                if _current_main(api, config) != subject["baseSha"]:
                    raise PolicyBlock("main advanced before Autofix evidence acquisition")
                _ensure_copilot_autofix(api, subject["number"])
                print(
                    json.dumps(
                        {
                            "alert": subject["number"],
                            "decision": "autofix-evidence-ready",
                            "routeRecordDigest": record["recordDigest"],
                        },
                        sort_keys=True,
                    )
                )
                return remaining_repairs + created

            if decision not in {
                "ordinary-deterministic-autoheal",
                "ordinary-bounded-autofix",
            }:
                print(
                    json.dumps(
                        {
                            "alert": number,
                            "decision": "route-blocked",
                            "routeDecision": decision,
                            "routeReason": record.get("reason"),
                            "routeRecordDigest": record.get("recordDigest"),
                        },
                        sort_keys=True,
                    )
                )
                continue

            subject = _subject_from_route(record)
            if prior >= config["maxAttemptsPerAlert"]:
                raise PolicyBlock(
                    "persisted route exceeded bounded automatic remediation attempts"
                )
            if route_evidence is None:
                raise PolicyBlock("persisted route artifact evidence is unavailable")
            _create_repair(
                api,
                subject,
                config,
                attempt=prior + 1,
                strategy=strategy,
                route_record=record,
                route_evidence=route_evidence,
            )
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
            return remaining_repairs + created
        except PolicyBlock as exc:
            number = alert.get("number")
            print(
                json.dumps(
                    {"alert": number, "decision": "blocked", "reason": str(exc)},
                    sort_keys=True,
                )
            )
    return remaining_repairs + created


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

    current_main_sha = "6" * 40
    canonical_codeql = {
        "id": 801,
        "run_attempt": 1,
        "name": MAIN_CODEQL_NAME,
        "path": MAIN_CODEQL_PATH,
        "head_branch": "main",
        "head_sha": current_main_sha,
        "event": "workflow_dispatch",
        "status": "queued",
        "conclusion": None,
    }
    selected_codeql = _select_main_codeql_run([canonical_codeql], current_main_sha)
    if selected_codeql != canonical_codeql:
        raise AutohealError("canonical exact-main CodeQL refresh run was not selected")
    for field, value in (
        ("head_sha", "5" * 40),
        ("path", ".github/workflows/ci.yml"),
        ("event", "pull_request"),
    ):
        drifted = {**canonical_codeql, field: value}
        if _select_main_codeql_run([drifted], current_main_sha) is not None:
            raise AutohealError(f"drifted exact-main CodeQL {field} was accepted")
    failed_codeql = {
        **canonical_codeql,
        "status": "completed",
        "conclusion": "failure",
    }
    if _select_main_codeql_run([failed_codeql], current_main_sha) is not None:
        raise AutohealError("failed exact-main CodeQL run was accepted as refresh evidence")

    class _MainCodeqlRefreshApi(GitHubApi):
        def __init__(self, *, move_main: bool = False, existing: bool = False) -> None:
            self.dispatched = False
            self.move_main = move_main
            self.existing = existing
            self.main_reads = 0
            self.calls: list[tuple[str, dict[str, Any] | None]] = []

        def get(self, path: str) -> Any:
            if path == "/branches/main":
                self.main_reads += 1
                observed = "4" * 40 if self.move_main and self.main_reads >= 2 else current_main_sha
                return {"commit": {"sha": observed}}
            raise AutohealError(f"unexpected CodeQL refresh self-test GET path: {path}")

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            expected = f"/actions/runs?head_sha={current_main_sha}"
            if path != expected or max_pages != 2:
                raise AutohealError(f"unexpected CodeQL refresh self-test list path: {path}")
            if self.existing or self.dispatched:
                row = {
                    **canonical_codeql,
                    "status": "completed" if self.existing else "queued",
                    "conclusion": "success" if self.existing else None,
                }
                return [row]
            return []

        def post(
            self,
            path: str,
            payload: dict[str, Any] | None = None,
            *,
            token: str | None = None,
        ) -> Any:
            if token is not None:
                raise AutohealError("CodeQL refresh self-test received unexpected alternate token")
            self.calls.append((path, payload))
            self.dispatched = True
            return None

    codeql_refresh_api = _MainCodeqlRefreshApi()
    codeql_refresh = _ensure_current_main_codeql(codeql_refresh_api, current_main_sha, config)
    expected_codeql_dispatch = (
        "/actions/workflows/codeql.yml/dispatches",
        {
            "ref": "main",
            "inputs": {"subject_sha": current_main_sha, "subject_ref": "main"},
        },
    )
    if codeql_refresh_api.calls != [expected_codeql_dispatch]:
        raise AutohealError("exact-main CodeQL refresh dispatch payload drifted")
    if codeql_refresh != {
        "codeqlRunId": 801,
        "codeqlRunAttempt": 1,
        "codeqlEvent": "workflow_dispatch",
        "codeqlStatus": "queued",
        "codeqlDispatched": True,
    }:
        raise AutohealError("exact-main CodeQL refresh evidence payload drifted")

    existing_codeql_api = _MainCodeqlRefreshApi(existing=True)
    existing_codeql = _ensure_current_main_codeql(existing_codeql_api, current_main_sha, config)
    if existing_codeql_api.calls:
        raise AutohealError("existing exact-main CodeQL success triggered a duplicate dispatch")
    if existing_codeql["codeqlDispatched"] is not False:
        raise AutohealError("existing exact-main CodeQL success was not reused")

    moved_codeql_api = _MainCodeqlRefreshApi(move_main=True)
    try:
        _ensure_current_main_codeql(moved_codeql_api, current_main_sha, config)
    except AutohealError as exc:
        if str(exc) != "current main changed after CodeQL refresh registration":
            raise AutohealError("moved-main CodeQL refresh guard changed semantics") from exc
    else:
        raise AutohealError("moved main was accepted after CodeQL refresh registration")

    merge_sha = "9" * 40
    base_sha = "a" * 40
    head_sha = "b" * 40
    canonical_ci = {
        "id": 901,
        "workflow_id": POST_MERGE_CI_WORKFLOW_ID,
        "run_attempt": 1,
        "name": POST_MERGE_CI_NAME,
        "path": POST_MERGE_CI_PATH,
        "head_branch": "main",
        "head_sha": merge_sha,
        "event": "push",
        "status": "queued",
        "conclusion": None,
    }
    selected = _select_post_merge_ci_run([canonical_ci], merge_sha)
    if selected != canonical_ci:
        raise AutohealError("canonical exact-main CI evidence was not selected")

    for field, value, expected_message in (
        ("head_sha", "8" * 40, "different head SHA"),
        ("path", ".github/workflows/codeql.yml", "mismatched workflow identity"),
        ("event", "pull_request", "unexpected event"),
    ):
        drifted = {**canonical_ci, field: value}
        try:
            _select_post_merge_ci_run([drifted], merge_sha)
        except AutohealError as exc:
            if expected_message not in str(exc):
                raise AutohealError(f"drifted post-merge CI {field} failed unexpectedly") from exc
        else:
            raise AutohealError(f"drifted post-merge CI {field} was accepted")

    try:
        _select_post_merge_ci_run([canonical_ci, {**canonical_ci, "id": 902}], merge_sha)
    except AutohealError as exc:
        if "ambiguous exact-subject CI evidence" not in str(exc):
            raise AutohealError("duplicate exact-main CI evidence failed unexpectedly") from exc
    else:
        raise AutohealError("duplicate exact-main CI evidence was accepted")

    for conclusion in ("failure", "cancelled", "timed_out"):
        failed = {
            **canonical_ci,
            "status": "completed",
            "conclusion": conclusion,
        }
        try:
            _select_post_merge_ci_run([failed], merge_sha)
        except AutohealError as exc:
            if f"non-successfully: {conclusion}" not in str(exc):
                raise AutohealError(
                    f"terminal {conclusion} CI evidence failed unexpectedly"
                ) from exc
        else:
            raise AutohealError(f"terminal {conclusion} CI evidence was accepted")

    source_tree = "6" * 40

    class _PostMergeEvidenceApi(GitHubApi):
        def __init__(self, *, move_main: bool = False, drift_tree: bool = False) -> None:
            self.move_main = move_main
            self.drift_tree = drift_tree

        def get(self, path: str) -> Any:
            if path == f"/git/commits/{merge_sha}":
                return {
                    "parents": [{"sha": base_sha}, {"sha": head_sha}],
                    "tree": {"sha": "5" * 40 if self.drift_tree else source_tree},
                }
            if path == f"/git/commits/{head_sha}":
                return {"tree": {"sha": source_tree}}
            if path == "/branches/main":
                return {"commit": {"sha": "7" * 40 if self.move_main else merge_sha}}
            raise AutohealError(f"unexpected post-merge self-test GET path: {path}")

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            if path == f"/actions/runs?head_sha={merge_sha}":
                if max_pages != 2:
                    raise AutohealError("post-merge CI pagination contract drifted")
                return [canonical_ci]
            raise AutohealError(f"unexpected post-merge self-test list path: {path}")

    post_merge_api = _PostMergeEvidenceApi()
    evidence = _finalize_post_merge_evidence(
        post_merge_api,
        {"sha": merge_sha},
        {"baseSha": base_sha, "headSha": head_sha},
        config,
    )
    if evidence != {
        "mergeSha": merge_sha,
        "sourceTreeSha": source_tree,
        "postMergeBinding": (
            "exact-current-main-parents-validated-source-tree-and-ci-registration"
        ),
        "postMergeCiWorkflowId": POST_MERGE_CI_WORKFLOW_ID,
        "postMergeCiRunId": 901,
        "postMergeCiRunAttempt": 1,
        "postMergeCiEvent": "push",
        "postMergeCiStatus": "queued",
        "postMergeCiDispatched": False,
    }:
        raise AutohealError("post-merge structural binding evidence payload drifted")

    drift_tree_api = _PostMergeEvidenceApi(drift_tree=True)
    try:
        _finalize_post_merge_evidence(
            drift_tree_api,
            {"sha": merge_sha},
            {"baseSha": base_sha, "headSha": head_sha},
            config,
        )
    except AutohealError as exc:
        if "merge tree differs from the validated repair head tree" not in str(exc):
            raise AutohealError("post-merge tree-drift guard changed semantics") from exc
    else:
        raise AutohealError("drifted post-merge source tree was accepted")

    moved_api = _PostMergeEvidenceApi(move_main=True)
    try:
        _finalize_post_merge_evidence(
            moved_api,
            {"sha": merge_sha},
            {"baseSha": base_sha, "headSha": head_sha},
            config,
        )
    except AutohealError as exc:
        expected = (
            f"main advanced during guarded security merge: expected {merge_sha}, got {'7' * 40}"
        )
        if str(exc) != expected:
            raise AutohealError("moved-main post-merge guard changed semantics") from exc
    else:
        raise AutohealError("moved main was accepted as post-merge binding authority")

    stale_lifecycle = {"state": "open", "draft": False, "mergeable": False}
    try:
        _require_repair_lifecycle(
            stale_lifecycle,
            {"base": "a" * 40},
            base_sha="a" * 40,
            main_sha="c" * 40,
        )
    except PolicyBlock as exc:
        if str(exc) != "generated repair is stale relative to current main":
            raise AutohealError("stale repair lifecycle ordering changed") from exc
    else:
        raise AutohealError("stale repair did not fail as stale")

    try:
        _require_repair_lifecycle(
            stale_lifecycle,
            {"base": "c" * 40},
            base_sha="c" * 40,
            main_sha="c" * 40,
        )
    except PolicyBlock as exc:
        if str(exc) != "generated repair PR is not definitively mergeable":
            raise AutohealError("repair mergeability guard changed semantics") from exc
    else:
        raise AutohealError("current non-mergeable repair did not fail closed")

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

    stale_marker_metadata = {
        "version": 1,
        "alert": 7,
        "attempt": 1,
        "base": "a" * 40,
        "head": "b" * 40,
        "fingerprint": "c" * 64,
        "generator": "deterministic",
        "path": "examples/reference_sut/app.py",
        "rule": "py/reflective-xss",
        "severity": 7.0,
        "strategy": REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    stale_body = _marker(stale_marker_metadata) + "\nGenerated repair."
    superseded_body = _with_stale_supersession_marker(
        stale_body,
        stale_marker_metadata,
        "d" * 40,
    )
    superseded_marker = _parse_marker(superseded_body)
    if (
        superseded_marker is None
        or superseded_marker.get("supersessionReason") != STALE_SUPERSESSION_REASON
        or superseded_marker.get("supersededByMain") != "d" * 40
    ):
        raise AutohealError("stale repair supersession marker binding failed")

    def _closed_repair_row(
        number: int,
        *,
        head: str,
        base: str,
        body: str,
        closed_at: str,
    ) -> dict[str, Any]:
        return {
            "number": number,
            "state": "closed",
            "merged_at": None,
            "closed_at": closed_at,
            "user": {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID},
            "head": {"ref": f"{BRANCH_PREFIX}7-{head[:12]}", "sha": head},
            "base": {"sha": base},
            "body": body,
        }

    explicit_metadata = dict(stale_marker_metadata)
    explicit_metadata["head"] = "1" * 40
    explicit_metadata["supersessionReason"] = STALE_SUPERSESSION_REASON
    explicit_metadata["supersededByMain"] = "f" * 40
    legacy_record = LEGACY_STALE_SUPERSESSIONS[207]
    legacy_metadata = dict(stale_marker_metadata)
    legacy_metadata["base"] = legacy_record["base"]
    legacy_metadata["head"] = legacy_record["head"]
    legacy_metadata["fingerprint"] = legacy_record["fingerprint"]
    future_metadata = dict(stale_marker_metadata)
    future_metadata["head"] = "3" * 40
    human_metadata = dict(stale_marker_metadata)
    human_metadata["head"] = "4" * 40
    forged_metadata = dict(stale_marker_metadata)
    forged_metadata["head"] = "5" * 40
    forged_metadata["supersessionReason"] = STALE_SUPERSESSION_REASON
    forged_metadata["supersededByMain"] = "f" * 40

    attempt_rows = [
        _closed_repair_row(
            101,
            head="1" * 40,
            base="a" * 40,
            body=_marker(explicit_metadata),
            closed_at="2026-09-23T00:20:00Z",
        ),
        _closed_repair_row(
            207,
            head=legacy_record["head"],
            base=legacy_record["base"],
            body=_marker(legacy_metadata),
            closed_at=legacy_record["closedAt"],
        ),
        _closed_repair_row(
            103,
            head="3" * 40,
            base="a" * 40,
            body=_marker(future_metadata),
            closed_at="2026-09-23T00:20:00Z",
        ),
        _closed_repair_row(
            104,
            head="4" * 40,
            base="a" * 40,
            body=_marker(human_metadata),
            closed_at="2026-09-23T00:10:00Z",
        ),
        _closed_repair_row(
            105,
            head="5" * 40,
            base="a" * 40,
            body=_marker(forged_metadata),
            closed_at="2026-09-23T00:20:00Z",
        ),
    ]
    explicit_certificate = _stale_supersession_certificate(
        explicit_metadata,
        101,
        "f" * 40,
        workflow_run_id=9001,
        workflow_run_attempt=1,
    )
    explicit_comment = {
        "id": 9001,
        "body": _stale_supersession_comment(explicit_certificate),
        "user": {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID},
        "created_at": "2026-09-23T00:19:59Z",
        "updated_at": "2026-09-23T00:19:59Z",
    }

    class _AttemptAccountingApi(GitHubApi):
        def __init__(self) -> None:
            pass

        def get(self, path: str) -> Any:
            if path == "/actions/runs/9001":
                return {
                    "id": 9001,
                    "workflow_id": SECURITY_AUTOHEAL_WORKFLOW_ID,
                    "path": SECURITY_AUTOHEAL_WORKFLOW_PATH,
                    "run_attempt": 1,
                    "event": "schedule",
                    "head_branch": "main",
                    "status": "completed",
                    "conclusion": "success",
                }
            raise AutohealError(f"unexpected attempt-accounting GET path: {path}")

        def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
            if path == "/pulls?state=closed&sort=updated&direction=desc":
                if max_pages != 10:
                    raise AutohealError("attempt-accounting pull pagination bound changed")
                return attempt_rows
            comment_match = re.fullmatch(r"/issues/([0-9]+)/comments", path)
            if comment_match is not None:
                if max_pages != 2:
                    raise AutohealError("attempt-accounting comment pagination bound changed")
                return [explicit_comment] if int(comment_match.group(1)) == 101 else []
            match = re.fullmatch(r"/issues/([0-9]+)/events", path)
            if match is None or max_pages != 2:
                raise AutohealError(f"unexpected attempt-accounting API path: {path}")
            number = int(match.group(1))
            actor = (
                {"login": "portyu9", "id": 35150859}
                if number == 104
                else {"login": GITHUB_ACTIONS_LOGIN, "id": GITHUB_ACTIONS_USER_ID}
            )
            row = next((item for item in attempt_rows if item["number"] == number), None)
            if row is None:
                raise AutohealError(f"unexpected attempt-accounting issue number: {number}")
            return [
                {
                    "id": number,
                    "event": "closed",
                    "created_at": row["closed_at"],
                    "actor": actor,
                }
            ]

    counted = _attempt_count(
        _AttemptAccountingApi(),
        7,
        REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
        "f" * 40,
    )
    if counted != 3:
        raise AutohealError(
            f"stale supersession attempt accounting changed: expected 3 counted attempts, got {counted}"
        )

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
    parser.add_argument("--plan-routes", action="store_true")
    parser.add_argument("--route-plan-output", type=Path)
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    parser.add_argument("--route-plan", type=Path)
    parser.add_argument("--route-artifact-id", type=int)
    parser.add_argument("--route-artifact-name")
    parser.add_argument("--route-artifact-digest")
    args = parser.parse_args()
    config = load_config()
    if args.validate_config:
        print("security-autoheal config: valid")
    if args.self_test:
        selftest(config)
    if args.plan_routes:
        if args.route_plan_output is None:
            parser.error("--plan-routes requires --route-plan-output")
        plan_routes(config, args.route_plan_output)
    if args.reconcile:
        if (
            args.route_plan is None
            or args.route_artifact_id is None
            or args.route_artifact_name is None
            or args.route_artifact_digest is None
        ):
            parser.error(
                "--reconcile requires --route-plan, --route-artifact-id, "
                "--route-artifact-name, and --route-artifact-digest"
            )
        reconcile(
            config,
            allow_merge=args.allow_merge,
            route_plan_path=args.route_plan,
            route_artifact_id=args.route_artifact_id,
            route_artifact_name=args.route_artifact_name,
            route_artifact_digest=args.route_artifact_digest,
        )
    if not (args.validate_config or args.self_test or args.plan_routes or args.reconcile):
        parser.error("choose --validate-config, --self-test, --plan-routes, or --reconcile")


if __name__ == "__main__":
    main()
