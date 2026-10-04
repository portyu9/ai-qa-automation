#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_alert_routing import (
    EXPECTED_BASE_BRANCH,
    EXPECTED_REPOSITORY,
    PROTECTED_REMEDIATION_STRATEGY,
    RoutingPolicyError,
    canonical_record,
    load_config,
    route_alert,
    route_alerts,
)
from security_owner_review import (
    PROTECTED_SECURITY_LANE,
    OwnerReviewError,
    OwnerReviewPolicyBlock,
    publish_exact_owner_approval,
    require_exact_owner_approval,
)
from trusted_status import (
    EXPECTED_GATE_EVENTS,
    EXPECTED_GATE_WORKFLOW_ID,
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

SCHEMA_VERSION = 1
AUTHORING_POLICY_VERSION = "protected-remediation-author-v1"
MAX_SOURCE_BYTES = 512 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_CHANGED_FILES = 1
MAX_API_BYTES = 8 * 1024 * 1024
MAX_OPEN_ALERTS = 100
MAX_PULL_HISTORY = 100
CONTROL_SHA_ENV = "PROTECTED_REMEDIATION_CONTROL_SHA"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
BRANCH_PREFIX = "automation/protected-security-remediation-"
BRANCH_RE = re.compile(
    r"^automation/protected-security-remediation-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$"
)
STAGING_BASE_PREFIX = "automation/protected-security-remediation-base-"
STAGING_BASE_RE = re.compile(
    r"^automation/protected-security-remediation-base-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$"
)
MARKER_PREFIX = "<!-- aiqa-protected-security-remediation:"
MARKER_SUFFIX = " -->"
ROUTE_TRAILER_PREFIX = "Protected-Route-Record-Digest: "
PLAN_TRAILER_PREFIX = "Protected-Repair-Plan-Digest: "
DISALLOWED_AUTHOR_BOTS = frozenset(
    {"github-actions[bot]", "trusted-pr-gate[bot]", "dependabot[bot]"}
)
TERMINAL_COMMENT_PREFIX = "<!-- aiqa-protected-security-remediation-terminal:"
TERMINAL_COMMENT_SUFFIX = " -->"
TERMINAL_SCHEMA_VERSION = 1
TERMINAL_CERTIFICATE_BOT_LOGIN = "github-actions[bot]"
TERMINAL_CERTIFICATE_BOT_ID = 41898282
TERMINAL_STATUS_PAGES = 4
TERMINAL_RUN_PAGE_SIZE = 100
TERMINAL_JOB_LIMIT = 100
TERMINAL_CI_WORKFLOW = "ci.yml"
TERMINAL_CI_WORKFLOW_ID = 339754724
TERMINAL_CI_WORKFLOW_NAME = "CI — ƳƤ AI QA Automation Framework"
TERMINAL_CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
TERMINAL_CI_REQUIRED_JOB = "Required PR Gate"
TERMINAL_CODEQL_WORKFLOW = "codeql.yml"
TERMINAL_CODEQL_WORKFLOW_ID = 359681647
TERMINAL_CODEQL_WORKFLOW_NAME = "CodeQL"
TERMINAL_CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"


class ProtectedRemediationError(RuntimeError):
    """Protected remediation input is malformed or outside reviewed authority."""


@dataclass(frozen=True)
class RepairStrategy:
    rule: str
    path: str
    author_strategy: str
    old: bytes
    new: bytes


_SECURITY_AUTOHEAL_LOG_OLD = b"""                _merge(api, number, validated_metadata, live, config)\n                print(\n                    json.dumps(\n                        {\n                            "pr": number,\n                            "decision": "repair-merged",\n                            "headSha": live["headSha"],\n                        },\n                        sort_keys=True,\n                    )\n                )\n"""

_SECURITY_AUTOHEAL_LOG_NEW = b"""                _merge(api, number, validated_metadata, live, config)\n                print(\n                    json.dumps(\n                        {\n                            "pr": number,\n                            "decision": "repair-merged",\n                        },\n                        sort_keys=True,\n                    )\n                )\n"""

REPAIR_STRATEGIES = (
    RepairStrategy(
        rule="py/clear-text-logging-sensitive-data",
        path=".github/scripts/security_autoheal.py",
        author_strategy="protected-security-autoheal-clear-text-log-v2",
        old=_SECURITY_AUTOHEAL_LOG_OLD,
        new=_SECURITY_AUTOHEAL_LOG_NEW,
    ),
)

# These assets define or certify this lane and therefore can never be repair targets for it.
SELF_AUTHORITY_PATHS = frozenset(
    {
        ".github/security-autoheal.json",
        ".github/scripts/dependency_governance.py",
        ".github/scripts/protected_security_remediation.py",
        ".github/scripts/security_alert_routing.py",
        ".github/scripts/security_owner_review.py",
        ".github/scripts/trusted_qualification.py",
        ".github/scripts/trusted_status.py",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
        ".github/workflows/post-merge-ci.yml",
        ".github/workflows/protected-security-remediation.yml",
        ".github/workflows/trusted-pr-auto.yml",
        "scripts/auto_trusted_bot_admission.py",
        "scripts/auto_trusted_preflight.py",
        "scripts/ci_contract_base.py",
        "scripts/ci_contract_trusted_auto.py",
        "scripts/trusted_pr_control.py",
        "scripts/verify_ci_contract.py",
        "scripts/verify_fork_cloud_authority.py",
    }
)


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise ProtectedRemediationError(f"{label} must be a canonical full SHA")
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        raise ProtectedRemediationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _strategy_for(record: Mapping[str, Any]) -> RepairStrategy:
    rule = record.get("rule")
    path = record.get("path")
    matches = [item for item in REPAIR_STRATEGIES if item.rule == rule and item.path == path]
    if len(matches) != 1:
        raise ProtectedRemediationError(
            "protected route has no exact code-owned authoring strategy"
        )
    strategy = matches[0]
    if strategy.path in SELF_AUTHORITY_PATHS:
        raise ProtectedRemediationError(
            "protected route targets the authoring lane's own authority"
        )
    return strategy


def validate_route_record(record: Mapping[str, Any], *, main_sha: str) -> RepairStrategy:
    _require_sha(main_sha, "current main SHA")
    try:
        canonical_record(record)
    except RoutingPolicyError as exc:
        raise ProtectedRemediationError(f"protected route record is not canonical: {exc}") from exc

    if record.get("schemaVersion") != 1:
        raise ProtectedRemediationError("protected route schema version is unsupported")
    if record.get("repository") != EXPECTED_REPOSITORY:
        raise ProtectedRemediationError("protected route repository identity drifted")
    if record.get("baseBranch") != EXPECTED_BASE_BRANCH:
        raise ProtectedRemediationError("protected route base branch drifted")
    if record.get("decision") != "protected-independent-remediation":
        raise ProtectedRemediationError(
            "route is not admitted for independent protected remediation"
        )
    if record.get("authority") != "protected-independent-remediation":
        raise ProtectedRemediationError("route authority is not the independent protected lane")
    if record.get("strategy") != PROTECTED_REMEDIATION_STRATEGY:
        raise ProtectedRemediationError("route strategy is not the reviewed protected strategy")
    if record.get("protected") is not True:
        raise ProtectedRemediationError("route is not classified as protected")
    if record.get("reason") != "protected-path-requires-independent-authority":
        raise ProtectedRemediationError("protected route reason drifted")
    if record.get("alertState") != "open" or record.get("alertInstanceState") != "open":
        raise ProtectedRemediationError("protected route is not bound to an open alert")
    if record.get("alertRef") != "refs/heads/main":
        raise ProtectedRemediationError("protected route is not bound to main")
    if record.get("baseSha") != main_sha or record.get("alertInstanceSha") != main_sha:
        raise ProtectedRemediationError("protected route is stale relative to exact current main")

    attempts = record.get("strategyAttemptCount")
    maximum = record.get("maxAttemptsPerStrategy")
    if (
        isinstance(attempts, bool)
        or not isinstance(attempts, int)
        or attempts < 0
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum < 1
        or attempts >= maximum
    ):
        raise ProtectedRemediationError("protected route attempt budget is invalid or exhausted")

    _require_digest(record.get("recordDigest"), "protected route record digest")
    _require_digest(record.get("fingerprint"), "protected route fingerprint")
    return _strategy_for(record)


def _canonical_plan_payload(plan: Mapping[str, Any], *, include_digest: bool) -> bytes:
    raw = dict(plan)
    if not include_digest:
        raw.pop("planDigest", None)
    return json.dumps(raw, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_plan(plan: Mapping[str, Any]) -> bytes:
    digest = _require_digest(plan.get("planDigest"), "protected repair plan digest")
    expected = hashlib.sha256(_canonical_plan_payload(plan, include_digest=False)).hexdigest()
    if digest != expected:
        raise ProtectedRemediationError("protected repair plan digest does not match its content")
    payload = _canonical_plan_payload(plan, include_digest=True) + b"\n"
    if len(payload) > MAX_PLAN_BYTES:
        raise ProtectedRemediationError(
            "protected repair plan exceeds the bounded persistence limit"
        )
    return payload


def build_repair_plan(
    source: bytes,
    record: Mapping[str, Any],
    *,
    main_sha: str,
) -> tuple[dict[str, Any], bytes]:
    strategy = validate_route_record(record, main_sha=main_sha)
    if not isinstance(source, bytes) or not source or len(source) > MAX_SOURCE_BYTES:
        raise ProtectedRemediationError(
            "protected repair source is empty or exceeds the ingestion bound"
        )
    if b"\x00" in source:
        raise ProtectedRemediationError("protected repair source is not canonical text")
    if source.count(strategy.old) != 1:
        raise ProtectedRemediationError(
            "protected repair source does not contain exactly one reviewed target"
        )

    repaired = source.replace(strategy.old, strategy.new, 1)
    if repaired == source or repaired.count(strategy.old) != 0:
        raise ProtectedRemediationError("protected deterministic transformation did not converge")
    if strategy.new not in repaired:
        raise ProtectedRemediationError(
            "protected deterministic transformation is not present after repair"
        )

    plan: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "policyVersion": AUTHORING_POLICY_VERSION,
        "repository": EXPECTED_REPOSITORY,
        "baseBranch": EXPECTED_BASE_BRANCH,
        "baseSha": main_sha,
        "alertNumber": record.get("alertNumber"),
        "fingerprint": record.get("fingerprint"),
        "routeRecordDigest": record.get("recordDigest"),
        "routeStrategy": record.get("strategy"),
        "authorStrategy": strategy.author_strategy,
        "attempt": int(record["strategyAttemptCount"]) + 1,
        "targetPath": strategy.path,
        "changedFiles": [strategy.path],
        "maxChangedFiles": MAX_CHANGED_FILES,
        "sourceSha256": hashlib.sha256(source).hexdigest(),
        "repairedSha256": hashlib.sha256(repaired).hexdigest(),
    }
    plan["planDigest"] = hashlib.sha256(
        _canonical_plan_payload(plan, include_digest=False)
    ).hexdigest()
    canonical_plan(plan)
    return plan, repaired


def revalidate_repair_plan(
    plan: Mapping[str, Any],
    source: bytes,
    record: Mapping[str, Any],
    *,
    main_sha: str,
) -> bytes:
    canonical_plan(plan)
    expected, repaired = build_repair_plan(source, record, main_sha=main_sha)
    if dict(plan) != expected:
        raise ProtectedRemediationError("protected repair plan drifted from exact live evidence")
    return repaired


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ProtectedRemediationError(f"{label} must be a positive integer")
    return value


def _require_author_identity(login: Any, user_id: Any) -> tuple[str, int]:
    if not isinstance(login, str) or not login.endswith("[bot]") or login in DISALLOWED_AUTHOR_BOTS:
        raise ProtectedRemediationError(
            "protected author App login is not an independent bot identity"
        )
    return login, _require_positive_int(user_id, "protected author App user id")


def _branch_for_attempt(alert_number: int, fingerprint: str, attempt: int) -> str:
    alert_number = _require_positive_int(alert_number, "protected repair alert number")
    fingerprint = _require_digest(fingerprint, "protected repair fingerprint")
    attempt = _require_positive_int(attempt, "protected repair attempt")
    branch = f"{BRANCH_PREFIX}{alert_number}-{fingerprint}-a{attempt}"
    if BRANCH_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError("protected repair branch is outside reviewed grammar")
    return branch


def branch_name(record: Mapping[str, Any]) -> str:
    validate_route_record(record, main_sha=_require_sha(record.get("baseSha"), "route base SHA"))
    return _branch_for_attempt(
        _require_positive_int(record.get("alertNumber"), "route alert number"),
        _require_digest(record.get("fingerprint"), "route fingerprint"),
        _require_positive_int(int(record["strategyAttemptCount"]) + 1, "protected repair attempt"),
    )


def _staging_base_name(record: Mapping[str, Any]) -> str:
    branch = branch_name(record)
    suffix = branch.removeprefix(BRANCH_PREFIX)
    staging = f"{STAGING_BASE_PREFIX}{suffix}"
    if STAGING_BASE_RE.fullmatch(staging) is None:
        raise ProtectedRemediationError("protected repair staging base is outside reviewed grammar")
    return staging


def repair_commit_message(record: Mapping[str, Any], plan: Mapping[str, Any]) -> str:
    route_digest = _require_digest(record.get("recordDigest"), "route record digest")
    plan_digest = _require_digest(plan.get("planDigest"), "repair plan digest")
    alert = _require_positive_int(record.get("alertNumber"), "route alert number")
    return (
        f"security: remediate protected CodeQL alert #{alert}\n\n"
        f"{ROUTE_TRAILER_PREFIX}{route_digest}\n"
        f"{PLAN_TRAILER_PREFIX}{plan_digest}"
    )


def _commit_trailer(message: Any, prefix: str, label: str) -> str:
    if not isinstance(message, str):
        raise ProtectedRemediationError("protected repair commit message is malformed")
    values = [line.removeprefix(prefix) for line in message.splitlines() if line.startswith(prefix)]
    if len(values) != 1:
        raise ProtectedRemediationError(
            f"protected repair commit has invalid {label} trailer count"
        )
    return _require_digest(values[0], f"protected repair commit {label}")


def marker(record: Mapping[str, Any], plan: Mapping[str, Any], *, head_sha: str) -> str:
    canonical_record(record)
    canonical_plan(plan)
    head_sha = _require_sha(head_sha, "protected repair head SHA")
    metadata = {
        "version": 1,
        "base": record.get("baseSha"),
        "head": head_sha,
        "routeRecord": dict(record),
        "repairPlan": dict(plan),
    }
    return (
        MARKER_PREFIX + json.dumps(metadata, separators=(",", ":"), sort_keys=True) + MARKER_SUFFIX
    )


def parse_marker(body: Any) -> dict[str, Any] | None:
    if not isinstance(body, str):
        return None
    rows = [
        line[len(MARKER_PREFIX) : -len(MARKER_SUFFIX)]
        for line in body.splitlines()
        if line.startswith(MARKER_PREFIX) and line.endswith(MARKER_SUFFIX)
    ]
    if len(rows) != 1:
        return None
    try:
        value = json.loads(rows[0])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _contents_bytes(api: Any, path: str, ref: str) -> bytes:
    payload = api.get(f"/contents/{path}?ref={ref}")
    if (
        not isinstance(payload, dict)
        or payload.get("type") != "file"
        or payload.get("encoding") != "base64"
        or not isinstance(payload.get("content"), str)
    ):
        raise ProtectedRemediationError(f"repository content is not one canonical file: {path}")
    encoded = payload["content"]
    compact = encoded.replace("\r", "").replace("\n", "")
    if not compact:
        raise ProtectedRemediationError(f"repository content base64 is invalid: {path}")
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtectedRemediationError(f"repository content base64 is invalid: {path}") from exc
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise ProtectedRemediationError(f"repository content is empty or oversized: {path}")
    return raw


def validate_generated_pr(
    api: Any,
    pr: Mapping[str, Any],
    *,
    expected_bot_login: str,
    expected_bot_id: int,
    config: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected_bot_login, expected_bot_id = _require_author_identity(
        expected_bot_login, expected_bot_id
    )
    if not isinstance(pr, Mapping) or pr.get("state") != "open" or pr.get("draft") is not False:
        raise ProtectedRemediationError("protected repair must be an open non-draft pull request")
    number = _require_positive_int(pr.get("number"), "protected repair PR number")
    user = pr.get("user") or {}
    if (
        user.get("login") != expected_bot_login
        or user.get("id") != expected_bot_id
        or user.get("type") != "Bot"
    ):
        raise ProtectedRemediationError("protected repair PR author is not the exact author App")

    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != EXPECTED_BASE_BRANCH
    ):
        raise ProtectedRemediationError("protected repair repository/base identity drifted")
    head_sha = _require_sha(head.get("sha"), "protected repair head SHA")
    base_sha = _require_sha(base.get("sha"), "protected repair base SHA")
    live = api.get(f"/branches/{EXPECTED_BASE_BRANCH}")
    live_main = _require_sha(
        ((live or {}).get("commit") or {}).get("sha"), "live protected repair main SHA"
    )
    if base_sha != live_main:
        raise ProtectedRemediationError("protected repair is stale relative to current main")

    metadata = parse_marker(pr.get("body"))
    if metadata is None or set(metadata) != {
        "version",
        "base",
        "head",
        "routeRecord",
        "repairPlan",
    }:
        raise ProtectedRemediationError("protected repair marker is missing or malformed")
    if (
        metadata.get("version") != 1
        or metadata.get("base") != base_sha
        or metadata.get("head") != head_sha
    ):
        raise ProtectedRemediationError("protected repair marker subject drifted")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("protected repair marker evidence is malformed")
    strategy = validate_route_record(record, main_sha=base_sha)
    canonical_plan(plan)
    if plan.get("baseSha") != base_sha or plan.get("targetPath") != strategy.path:
        raise ProtectedRemediationError("protected repair plan subject drifted")
    if (
        plan.get("changedFiles") != [strategy.path]
        or plan.get("maxChangedFiles") != MAX_CHANGED_FILES
    ):
        raise ProtectedRemediationError("protected repair changed-file authority drifted")
    if head.get("ref") != branch_name(record):
        raise ProtectedRemediationError(
            "protected repair branch does not match exact route subject"
        )

    alert_number = _require_positive_int(record.get("alertNumber"), "protected route alert number")
    alert = api.get(f"/code-scanning/alerts/{alert_number}")
    if not isinstance(alert, dict):
        raise ProtectedRemediationError("live protected CodeQL alert is missing or malformed")
    policy = load_config() if config is None else config
    try:
        rebound = route_alert(
            alert,
            main_sha=base_sha,
            config=policy,
            attempts_by_strategy={
                PROTECTED_REMEDIATION_STRATEGY: int(record["strategyAttemptCount"])
            },
            expected_fingerprint=str(record["fingerprint"]),
            expected_strategy=PROTECTED_REMEDIATION_STRATEGY,
        )
    except RoutingPolicyError as exc:
        raise ProtectedRemediationError(f"live protected route reproof failed: {exc}") from exc
    if rebound != record:
        raise ProtectedRemediationError(
            "live protected route drifted from persisted repair evidence"
        )

    base_source = _contents_bytes(api, strategy.path, base_sha)
    repaired = revalidate_repair_plan(plan, base_source, record, main_sha=base_sha)
    if _contents_bytes(api, strategy.path, head_sha) != repaired:
        raise ProtectedRemediationError(
            "protected repair head bytes do not equal deterministic output"
        )

    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    if (
        len(files) != 1
        or not isinstance(files[0], dict)
        or files[0].get("filename") != strategy.path
        or files[0].get("status") != "modified"
    ):
        raise ProtectedRemediationError(
            "protected repair diff escaped the exact one-file authority"
        )

    commit = api.get(f"/commits/{head_sha}")
    if not isinstance(commit, dict) or commit.get("sha") != head_sha:
        raise ProtectedRemediationError("protected repair head commit is missing")
    author = commit.get("author") or {}
    parents = commit.get("parents")
    message = (commit.get("commit") or {}).get("message")
    if (
        author.get("login") != expected_bot_login
        or author.get("id") != expected_bot_id
        or author.get("type") != "Bot"
    ):
        raise ProtectedRemediationError(
            "protected repair commit author is not the exact author App"
        )
    if (
        not isinstance(parents, list)
        or len(parents) != 1
        or (parents[0] or {}).get("sha") != base_sha
    ):
        raise ProtectedRemediationError(
            "protected repair commit is not directly parented to exact main"
        )
    if _commit_trailer(message, ROUTE_TRAILER_PREFIX, "route digest") != record["recordDigest"]:
        raise ProtectedRemediationError("protected repair commit route digest drifted")
    if _commit_trailer(message, PLAN_TRAILER_PREFIX, "plan digest") != plan["planDigest"]:
        raise ProtectedRemediationError("protected repair commit plan digest drifted")
    if message != repair_commit_message(record, plan):
        raise ProtectedRemediationError("protected repair commit message is not canonical")

    return {
        "number": number,
        "headSha": head_sha,
        "baseSha": base_sha,
        "alertNumber": alert_number,
        "targetPath": strategy.path,
        "routeRecordDigest": record["recordDigest"],
        "planDigest": plan["planDigest"],
        "authorStrategy": plan["authorStrategy"],
    }


class GitHubApi:
    def __init__(self, token: str, repository: str) -> None:
        if repository != EXPECTED_REPOSITORY:
            raise ProtectedRemediationError(
                "protected remediation is bound to the reviewed repository"
            )
        if not token:
            raise ProtectedRemediationError("protected remediation GitHub token is required")
        self.token = token
        self.repository = repository
        self.base_url = f"https://api.github.com/repos/{repository}"

    def request_status(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> tuple[int, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise ProtectedRemediationError("GitHub API path must be repository-local")
        data = None
        if payload is not None:
            data = json.dumps(dict(payload), separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "yp-ai-qa-protected-remediation",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(MAX_API_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_API_BYTES + 1)
            status = exc.code
        except urllib.error.URLError as exc:
            raise ProtectedRemediationError(f"GitHub API {method} transport failure") from exc
        if len(raw) > MAX_API_BYTES:
            raise ProtectedRemediationError("GitHub API response exceeded bounded ingestion")
        if not raw:
            parsed: Any = {}
        else:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ProtectedRemediationError(
                    f"GitHub API {method} returned malformed JSON"
                ) from exc
        return status, parsed

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
    ) -> Any:
        status, parsed = self.request_status(method, path, payload)
        if status < 200 or status >= 300:
            raise ProtectedRemediationError(
                f"GitHub API {method} {path.split('?', 1)[0]} failed with status {status}"
            )
        return parsed

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("POST", path, payload)

    def put(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("PUT", path, payload)

    def patch(self, path: str, payload: Mapping[str, Any]) -> Any:
        return self.request("PATCH", path, payload)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)

    def list_all(
        self,
        path: str,
        *,
        max_pages: int = 4,
        max_items: int | None = None,
    ) -> list[dict[str, Any]]:
        if max_pages < 1:
            raise ProtectedRemediationError("pagination max_pages must be positive")
        if max_items is not None and max_items < 1:
            raise ProtectedRemediationError("pagination max_items must be positive")
        rows: list[dict[str, Any]] = []
        page_size = 100 if max_items is None else min(100, max_items)
        separator = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            payload = self.get(f"{path}{separator}per_page={page_size}&page={page}")
            if not isinstance(payload, list):
                raise ProtectedRemediationError("GitHub paginated response is not a list")
            for item in payload:
                if not isinstance(item, dict):
                    raise ProtectedRemediationError(
                        "GitHub paginated response contains a non-object item"
                    )
                rows.append(item)
                if max_items is not None and len(rows) >= max_items:
                    return rows
            if len(payload) < page_size:
                return rows
        raise ProtectedRemediationError("GitHub pagination reached the reviewed page bound")


def _generated_bot_pull(pr: Mapping[str, Any], *, login: str, user_id: int) -> bool:
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    branch = head.get("ref")
    return (
        user.get("login") == login
        and user.get("id") == user_id
        and user.get("type") == "Bot"
        and isinstance(branch, str)
        and BRANCH_RE.fullmatch(branch) is not None
    )


def _pulls_for_branch(api: GitHubApi, branch: str) -> list[dict[str, Any]]:
    if BRANCH_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError("protected repair branch lookup escaped reviewed grammar")
    owner = EXPECTED_REPOSITORY.split("/", 1)[0]
    query = urllib.parse.urlencode(
        {"state": "all", "head": f"{owner}:{branch}"},
        quote_via=urllib.parse.quote,
    )
    pulls = api.list_all(f"/pulls?{query}", max_pages=1, max_items=2)
    matches = [
        pr
        for pr in pulls
        if isinstance(pr.get("head"), dict)
        and pr["head"].get("ref") == branch
        and ((pr["head"].get("repo") or {}).get("full_name")) == EXPECTED_REPOSITORY
    ]
    if len(matches) > 1:
        raise ProtectedRemediationError("protected repair branch maps to multiple pull requests")
    return matches


def _attempt_count(
    api: GitHubApi,
    *,
    alert_number: int,
    fingerprint: str,
    bot_login: str,
    bot_id: int,
    max_attempts: int,
) -> int:
    max_attempts = _require_positive_int(max_attempts, "protected repair maximum attempts")
    if max_attempts > MAX_PULL_HISTORY:
        raise ProtectedRemediationError("protected repair attempt budget exceeds history bound")
    attempts: set[int] = set()
    for expected_attempt in range(1, max_attempts + 1):
        branch = _branch_for_attempt(alert_number, fingerprint, expected_attempt)
        pulls = _pulls_for_branch(api, branch)
        if not pulls:
            continue
        pr = pulls[0]
        if not _generated_bot_pull(pr, login=bot_login, user_id=bot_id):
            raise ProtectedRemediationError(
                "protected repair history branch is not owned by the exact author App"
            )
        metadata = parse_marker(pr.get("body"))
        if metadata is None:
            raise ProtectedRemediationError(
                "generated protected repair has malformed history marker"
            )
        record = metadata.get("routeRecord")
        plan = metadata.get("repairPlan")
        if not isinstance(record, dict) or not isinstance(plan, dict):
            raise ProtectedRemediationError(
                "generated protected repair history evidence is malformed"
            )
        try:
            canonical_record(record)
            canonical_plan(plan)
        except (RoutingPolicyError, ProtectedRemediationError) as exc:
            raise ProtectedRemediationError(
                "generated protected repair history evidence is not canonical"
            ) from exc
        if (
            record.get("alertNumber") != alert_number
            or record.get("fingerprint") != fingerprint
            or record.get("strategy") != PROTECTED_REMEDIATION_STRATEGY
        ):
            raise ProtectedRemediationError(
                "protected repair history branch evidence drifted from exact subject"
            )
        attempt = _require_positive_int(plan.get("attempt"), "historical protected attempt")
        if attempt != expected_attempt or pr.get("head", {}).get("ref") != branch_name(record):
            raise ProtectedRemediationError("generated protected repair history branch drifted")
        attempts.add(attempt)
    if attempts and attempts != set(range(1, max(attempts) + 1)):
        raise ProtectedRemediationError("protected repair attempt history is non-contiguous")
    return len(attempts)


def _current_main(api: GitHubApi) -> str:
    branch = api.get(f"/branches/{EXPECTED_BASE_BRANCH}")
    return _require_sha(((branch or {}).get("commit") or {}).get("sha"), "current main SHA")


def _required_control_sha() -> str:
    return _require_sha(
        os.environ.get(CONTROL_SHA_ENV),
        "trusted protected-remediation control SHA",
    )


def require_current_control_revision(api: GitHubApi, expected_sha: str) -> str:
    expected = _require_sha(expected_sha, "trusted protected-remediation control SHA")
    observed = _current_main(api)
    if observed != expected:
        raise ProtectedRemediationError(
            "trusted protected-remediation control revision is stale relative to current main"
        )
    return observed


def _require_branch_unclaimed_by_open_pr(api: GitHubApi, branch: str) -> None:
    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    for row in rows:
        head = row.get("head") or {}
        if (
            row.get("state") == "open"
            and head.get("ref") == branch
            and (head.get("repo") or {}).get("full_name") == EXPECTED_REPOSITORY
        ):
            raise ProtectedRemediationError(
                "protected repair branch became claimed by an open PR before rollback"
            )


def _delete_exact_generated_branch(
    read_api: GitHubApi,
    write_api: GitHubApi,
    branch: str,
    expected_sha: str,
) -> None:
    if BRANCH_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError("protected repair rollback branch escaped reviewed grammar")
    expected_sha = _require_sha(expected_sha, "protected repair rollback head SHA")
    encoded_ref = urllib.parse.quote(branch, safe="")
    status, ref = read_api.request_status("GET", f"/git/ref/heads/{encoded_ref}")
    if status == 404:
        return
    if status != 200 or not isinstance(ref, dict):
        raise ProtectedRemediationError("protected repair rollback ref lookup failed")

    def require_exact_ref_sha(payload: dict[str, Any], *, label: str) -> str:
        obj = payload.get("object") or {}
        if (
            payload.get("ref") != f"refs/heads/{branch}"
            or not isinstance(obj, dict)
            or obj.get("type") != "commit"
        ):
            raise ProtectedRemediationError(f"protected repair {label} ref identity drifted")
        return _require_sha(
            obj.get("sha"),
            f"protected repair {label} ref SHA",
        )

    observed = require_exact_ref_sha(ref, label="rollback")
    if observed != expected_sha:
        raise ProtectedRemediationError("protected repair branch changed before exact rollback")
    _require_branch_unclaimed_by_open_pr(read_api, branch)
    terminal_status, terminal_ref = read_api.request_status(
        "GET",
        f"/git/ref/heads/{encoded_ref}",
    )
    if terminal_status == 404:
        return
    if terminal_status != 200 or not isinstance(terminal_ref, dict):
        raise ProtectedRemediationError("protected repair rollback terminal ref lookup failed")
    terminal_sha = require_exact_ref_sha(terminal_ref, label="rollback terminal")
    if terminal_sha != expected_sha:
        raise ProtectedRemediationError(
            "protected repair branch changed at terminal rollback boundary"
        )
    delete_error: ProtectedRemediationError | None = None
    try:
        write_api.delete(f"/git/refs/heads/{encoded_ref}")
    except ProtectedRemediationError as exc:
        delete_error = exc
    final_status, _ = read_api.request_status("GET", f"/git/ref/heads/{encoded_ref}")
    if final_status == 404:
        return
    if delete_error is not None:
        raise ProtectedRemediationError(
            "protected repair branch deletion outcome is not durably closed"
        ) from delete_error
    raise ProtectedRemediationError("protected repair branch deletion was not durable")


def _staging_ref_sha(api: GitHubApi, branch: str) -> str | None:
    if STAGING_BASE_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError("protected repair staging ref escaped reviewed grammar")
    encoded = urllib.parse.quote(branch, safe="")
    status, payload = api.request_status("GET", f"/git/ref/heads/{encoded}")
    if status == 404:
        return None
    if status != 200 or not isinstance(payload, dict):
        raise ProtectedRemediationError("protected repair staging ref lookup failed")
    obj = payload.get("object") or {}
    if (
        payload.get("ref") != f"refs/heads/{branch}"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
    ):
        raise ProtectedRemediationError("protected repair staging ref identity drifted")
    return _require_sha(obj.get("sha"), "protected repair staging ref SHA")


def _require_staging_ref_unclaimed(api: GitHubApi, branch: str) -> None:
    rows = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=4)
    for row in rows:
        if row.get("state") != "open":
            continue
        for role in ("head", "base"):
            subject = row.get(role) or {}
            if (
                subject.get("ref") == branch
                and (subject.get("repo") or {}).get("full_name") == EXPECTED_REPOSITORY
            ):
                raise ProtectedRemediationError(
                    f"protected repair staging ref became claimed as PR {role} before cleanup"
                )


def _delete_exact_staging_base(
    read_api: GitHubApi,
    write_api: GitHubApi,
    branch: str,
    base_sha: str,
) -> None:
    base_sha = _require_sha(base_sha, "protected repair staging cleanup base SHA")
    observed = _staging_ref_sha(read_api, branch)
    if observed is None:
        return
    if observed != base_sha:
        raise ProtectedRemediationError("protected repair staging ref changed before cleanup")
    _require_staging_ref_unclaimed(read_api, branch)
    terminal = _staging_ref_sha(read_api, branch)
    if terminal != base_sha:
        raise ProtectedRemediationError(
            "protected repair staging ref changed at terminal cleanup boundary"
        )
    encoded = urllib.parse.quote(branch, safe="")
    delete_error: ProtectedRemediationError | None = None
    try:
        write_api.delete(f"/git/refs/heads/{encoded}")
    except ProtectedRemediationError as exc:
        delete_error = exc
    if _staging_ref_sha(read_api, branch) is None:
        return
    if delete_error is not None:
        raise ProtectedRemediationError(
            "protected repair staging ref deletion outcome is not durably closed"
        ) from delete_error
    raise ProtectedRemediationError("protected repair staging ref deletion was not durable")


def _ensure_staging_base_ref(
    read_api: GitHubApi,
    write_api: GitHubApi,
    record: Mapping[str, Any],
) -> str:
    branch = _staging_base_name(record)
    base_sha = _require_sha(record.get("baseSha"), "protected repair staging base SHA")
    observed = _staging_ref_sha(read_api, branch)
    if observed is None:
        creation_error: ProtectedRemediationError | None = None
        created: Any = None
        try:
            created = write_api.post(
                "/git/refs",
                {"ref": f"refs/heads/{branch}", "sha": base_sha},
            )
        except ProtectedRemediationError as exc:
            creation_error = exc
        response_exact = False
        if creation_error is None and isinstance(created, dict):
            obj = created.get("object") or {}
            response_exact = (
                created.get("ref") == f"refs/heads/{branch}"
                and isinstance(obj, dict)
                and obj.get("type") in {None, "commit"}
                and obj.get("sha") == base_sha
            )
        observed = _staging_ref_sha(read_api, branch)
        if observed != base_sha:
            if creation_error is not None:
                raise ProtectedRemediationError(
                    "protected repair staging ref creation failed ambiguously; "
                    "retaining the exact generated ref for recovery"
                ) from creation_error
            if not response_exact:
                raise ProtectedRemediationError(
                    "protected repair staging ref creation response was ambiguous and "
                    "exact read-back did not converge"
                )
            raise ProtectedRemediationError(
                "created protected repair staging ref failed exact read-back"
            )
    elif observed != base_sha:
        raise ProtectedRemediationError("protected repair staging ref exists at an unexpected SHA")
    return branch


def _validate_repair_publication_identity(
    pr: Any,
    *,
    number: int,
    branch: str,
    head_sha: str,
    base_ref: str,
    base_sha: str,
    title: str,
    body: str,
    bot_login: str,
    bot_id: int,
) -> None:
    if not isinstance(pr, dict):
        raise ProtectedRemediationError("protected repair publication returned malformed PR data")
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        pr.get("number") != number
        or pr.get("state") != "open"
        or pr.get("draft") is not False
        or pr.get("title") != title
        or pr.get("body") != body
        or user.get("login") != bot_login
        or user.get("id") != bot_id
        or user.get("type") != "Bot"
        or head.get("ref") != branch
        or _require_sha(head.get("sha"), "protected repair publication head SHA") != head_sha
        or (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != base_ref
        or _require_sha(base.get("sha"), "protected repair publication base SHA") != base_sha
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ProtectedRemediationError(
            "protected repair publication identity drifted from the exact subject"
        )


def _retarget_staged_repair_pr(
    read_api: GitHubApi,
    write_api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any]:
    metadata = parse_marker(pr.get("body"))
    if metadata is None or set(metadata) != {
        "version",
        "base",
        "head",
        "routeRecord",
        "repairPlan",
    }:
        raise ProtectedRemediationError("staged protected repair marker is missing or malformed")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("staged protected repair evidence is malformed")
    base_sha = _require_sha(metadata.get("base"), "staged protected repair marker base SHA")
    head_sha = _require_sha(metadata.get("head"), "staged protected repair marker head SHA")
    if base_sha != _require_sha(control_sha, "staged protected repair control SHA"):
        raise ProtectedRemediationError("staged protected repair is not bound to trusted control")
    strategy = validate_route_record(record, main_sha=base_sha)
    canonical_plan(plan)
    if (
        plan.get("baseSha") != base_sha
        or plan.get("targetPath") != strategy.path
        or plan.get("changedFiles") != [strategy.path]
        or plan.get("maxChangedFiles") != MAX_CHANGED_FILES
    ):
        raise ProtectedRemediationError("staged protected repair plan authority drifted")
    branch = branch_name(record)
    staging_base = _staging_base_name(record)
    number = _require_positive_int(pr.get("number"), "staged protected repair PR number")
    title = f"security: remediate protected CodeQL alert #{record['alertNumber']}"
    body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + marker(record, plan, head_sha=head_sha)
    )
    _validate_repair_publication_identity(
        pr,
        number=number,
        branch=branch,
        head_sha=head_sha,
        base_ref=staging_base,
        base_sha=base_sha,
        title=title,
        body=body,
        bot_login=bot_login,
        bot_id=bot_id,
    )
    require_current_control_revision(read_api, control_sha)
    if _staging_ref_sha(read_api, staging_base) != base_sha:
        raise ProtectedRemediationError("protected repair staging ref drifted before retarget")

    patch_error: ProtectedRemediationError | None = None
    try:
        write_api.patch(f"/pulls/{number}", {"base": EXPECTED_BASE_BRANCH})
    except ProtectedRemediationError as exc:
        patch_error = exc
    try:
        retargeted = read_api.get(f"/pulls/{number}")
        _validate_repair_publication_identity(
            retargeted,
            number=number,
            branch=branch,
            head_sha=head_sha,
            base_ref=EXPECTED_BASE_BRANCH,
            base_sha=base_sha,
            title=title,
            body=body,
            bot_login=bot_login,
            bot_id=bot_id,
        )
    except ProtectedRemediationError as exc:
        if patch_error is not None:
            raise ProtectedRemediationError(
                "protected repair retarget failed ambiguously; retaining exact staging "
                "and generated refs for recovery"
            ) from patch_error
        raise ProtectedRemediationError(
            "protected repair retarget did not converge; retaining exact staging "
            "and generated refs for recovery"
        ) from exc

    require_current_control_revision(read_api, control_sha)
    _delete_exact_staging_base(read_api, write_api, staging_base, base_sha)
    return dict(retargeted)


def _recover_repair_publication(
    read_api: GitHubApi,
    write_api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any] | None:
    metadata = parse_marker(pr.get("body"))
    if metadata is None or set(metadata) != {
        "version",
        "base",
        "head",
        "routeRecord",
        "repairPlan",
    }:
        raise ProtectedRemediationError("protected repair recovery marker is missing or malformed")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("protected repair recovery evidence is malformed")
    marker_base = _require_sha(metadata.get("base"), "protected repair recovery base SHA")
    head_sha = _require_sha(metadata.get("head"), "protected repair recovery head SHA")
    strategy = validate_route_record(record, main_sha=marker_base)
    canonical_plan(plan)
    if (
        plan.get("baseSha") != marker_base
        or plan.get("targetPath") != strategy.path
        or plan.get("changedFiles") != [strategy.path]
        or plan.get("maxChangedFiles") != MAX_CHANGED_FILES
    ):
        raise ProtectedRemediationError("protected repair recovery plan authority drifted")
    branch = branch_name(record)
    staging_base = _staging_base_name(record)
    number = _require_positive_int(pr.get("number"), "protected repair recovery PR number")
    title = f"security: remediate protected CodeQL alert #{record['alertNumber']}"
    body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + marker(record, plan, head_sha=head_sha)
    )
    base_ref = (pr.get("base") or {}).get("ref")
    current_main = _current_main(read_api)

    if base_ref == staging_base:
        _validate_repair_publication_identity(
            pr,
            number=number,
            branch=branch,
            head_sha=head_sha,
            base_ref=staging_base,
            base_sha=marker_base,
            title=title,
            body=body,
            bot_login=bot_login,
            bot_id=bot_id,
        )
        if current_main != marker_base:
            _rollback_created_repair_pr(
                read_api,
                write_api,
                number=number,
                branch=branch,
                head_sha=head_sha,
                title=title,
                body=body,
                bot_login=bot_login,
                bot_id=bot_id,
                expected_base_ref=staging_base,
                expected_base_sha=marker_base,
            )
            return None
        return _retarget_staged_repair_pr(
            read_api,
            write_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )

    if base_ref == EXPECTED_BASE_BRANCH:
        if current_main == marker_base:
            _validate_repair_publication_identity(
                pr,
                number=number,
                branch=branch,
                head_sha=head_sha,
                base_ref=EXPECTED_BASE_BRANCH,
                base_sha=marker_base,
                title=title,
                body=body,
                bot_login=bot_login,
                bot_id=bot_id,
            )
            retained_staging = _staging_ref_sha(read_api, staging_base)
            if retained_staging is not None:
                if retained_staging != marker_base:
                    raise ProtectedRemediationError(
                        "retained protected repair staging ref changed after retarget"
                    )
                _delete_exact_staging_base(
                    read_api,
                    write_api,
                    staging_base,
                    marker_base,
                )
        return dict(pr)

    raise ProtectedRemediationError(
        "protected repair publication base escaped main/staging authority"
    )


def _protected_route_candidates(
    api: GitHubApi,
    *,
    main_sha: str,
    config: Mapping[str, Any],
    bot_login: str,
    bot_id: int,
) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {"state": "open", "ref": "refs/heads/main", "tool_name": "CodeQL"},
        quote_via=urllib.parse.quote,
    )
    alerts = api.list_all(
        f"/code-scanning/alerts?{query}",
        max_pages=2,
        max_items=MAX_OPEN_ALERTS + 1,
    )
    if len(alerts) > MAX_OPEN_ALERTS:
        raise ProtectedRemediationError("open CodeQL alert set exceeds the reviewed bound")
    attempts: dict[int, dict[str, int]] = {}
    for alert in alerts:
        number = _require_positive_int(alert.get("number"), "CodeQL alert number")
        provisional = route_alert(alert, main_sha=main_sha, config=config)
        fingerprint = provisional.get("fingerprint")
        if not isinstance(fingerprint, str):
            raise ProtectedRemediationError("CodeQL route fingerprint is malformed")
        attempts[number] = {PROTECTED_REMEDIATION_STRATEGY: 0}
        if provisional.get("decision") == "protected-independent-remediation":
            attempts[number][PROTECTED_REMEDIATION_STRATEGY] = _attempt_count(
                api,
                alert_number=number,
                fingerprint=fingerprint,
                bot_login=bot_login,
                bot_id=bot_id,
                max_attempts=_require_positive_int(
                    provisional.get("maxAttemptsPerStrategy"),
                    "protected route maximum attempts",
                ),
            )
    try:
        records = route_alerts(
            alerts,
            main_sha=main_sha,
            config=config,
            attempts_by_alert=attempts,
        )
    except RoutingPolicyError as exc:
        raise ProtectedRemediationError(f"protected routing failed closed: {exc}") from exc
    return [
        record
        for record in records
        if record.get("decision") == "protected-independent-remediation"
    ]


def _exact_repair_evidence(
    api: GitHubApi,
    record: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], bytes, bytes]:
    base_sha = _require_sha(record.get("baseSha"), "protected repair base SHA")
    if _current_main(api) != base_sha:
        raise ProtectedRemediationError("main moved before protected repair reproof")
    alert_number = _require_positive_int(record.get("alertNumber"), "protected alert number")
    alert = api.get(f"/code-scanning/alerts/{alert_number}")
    attempts = int(record.get("strategyAttemptCount", -1))
    try:
        rebound = route_alert(
            alert,
            main_sha=base_sha,
            config=config,
            attempts_by_strategy={PROTECTED_REMEDIATION_STRATEGY: attempts},
            expected_fingerprint=str(record.get("fingerprint")),
            expected_strategy=PROTECTED_REMEDIATION_STRATEGY,
        )
    except RoutingPolicyError as exc:
        raise ProtectedRemediationError(f"protected alert reproof failed closed: {exc}") from exc
    if rebound != record:
        raise ProtectedRemediationError("protected route changed before authoring")
    strategy = validate_route_record(record, main_sha=base_sha)
    source = _contents_bytes(api, strategy.path, base_sha)
    plan, repaired = build_repair_plan(source, record, main_sha=base_sha)

    if _current_main(api) != base_sha:
        raise ProtectedRemediationError("main moved during protected repair reproof")
    alert_after = api.get(f"/code-scanning/alerts/{alert_number}")
    try:
        rebound_after = route_alert(
            alert_after,
            main_sha=base_sha,
            config=config,
            attempts_by_strategy={PROTECTED_REMEDIATION_STRATEGY: attempts},
            expected_fingerprint=str(record.get("fingerprint")),
            expected_strategy=PROTECTED_REMEDIATION_STRATEGY,
        )
    except RoutingPolicyError as exc:
        raise ProtectedRemediationError(
            f"final protected alert reproof failed closed: {exc}"
        ) from exc
    if rebound_after != record:
        raise ProtectedRemediationError("protected route changed at authoring boundary")
    if _contents_bytes(api, strategy.path, base_sha) != source:
        raise ProtectedRemediationError("protected target source changed during authoring reproof")
    return plan, source, repaired


def _create_repair_commit(
    read_api: GitHubApi,
    write_api: GitHubApi,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    repaired: bytes,
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> tuple[str, bool]:
    branch = branch_name(record)
    base_sha = _require_sha(record.get("baseSha"), "protected repair base SHA")
    control_sha = _require_sha(control_sha, "trusted protected-remediation control SHA")
    if base_sha != control_sha:
        raise ProtectedRemediationError("protected repair base is not the trusted control revision")
    require_current_control_revision(read_api, control_sha)
    encoded_ref = urllib.parse.quote(branch, safe="")
    status, existing = read_api.request_status("GET", f"/git/ref/heads/{encoded_ref}")
    created_ref = False
    if status == 200:
        if not isinstance(existing, dict):
            raise ProtectedRemediationError("existing protected repair ref is malformed")
        commit_sha = _require_sha(
            ((existing.get("object") or {}).get("sha")), "existing protected repair ref SHA"
        )
    elif status == 404:
        base_commit = read_api.get(f"/git/commits/{base_sha}")
        base_tree = _require_sha(
            ((base_commit or {}).get("tree") or {}).get("sha"), "protected repair base tree SHA"
        )
        try:
            text = repaired.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtectedRemediationError("protected repair output is not UTF-8 text") from exc
        require_current_control_revision(read_api, control_sha)
        blob = write_api.post("/git/blobs", {"content": text, "encoding": "utf-8"})
        blob_sha = _require_sha((blob or {}).get("sha"), "protected repair blob SHA")
        require_current_control_revision(read_api, control_sha)
        tree = write_api.post(
            "/git/trees",
            {
                "base_tree": base_tree,
                "tree": [
                    {
                        "path": plan["targetPath"],
                        "mode": "100644",
                        "type": "blob",
                        "sha": blob_sha,
                    }
                ],
            },
        )
        tree_sha = _require_sha((tree or {}).get("sha"), "protected repair tree SHA")
        require_current_control_revision(read_api, control_sha)
        commit = write_api.post(
            "/git/commits",
            {
                "message": repair_commit_message(record, plan),
                "tree": tree_sha,
                "parents": [base_sha],
            },
        )
        commit_sha = _require_sha((commit or {}).get("sha"), "protected repair commit SHA")
        require_current_control_revision(read_api, control_sha)
        created = write_api.post(
            "/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": commit_sha},
        )
        if (
            not isinstance(created, dict)
            or created.get("ref") != f"refs/heads/{branch}"
            or ((created.get("object") or {}).get("sha")) != commit_sha
        ):
            raise ProtectedRemediationError("GitHub did not acknowledge exact protected repair ref")
        created_ref = True
        try:
            require_current_control_revision(read_api, control_sha)
        except ProtectedRemediationError:
            _delete_exact_generated_branch(read_api, write_api, branch, commit_sha)
            raise
    else:
        raise ProtectedRemediationError(f"protected repair ref lookup failed with status {status}")

    try:
        commit = read_api.get(f"/commits/{commit_sha}")
        author = (commit or {}).get("author") if isinstance(commit, dict) else None
        parents = (commit or {}).get("parents") if isinstance(commit, dict) else None
        message = (
            ((commit or {}).get("commit") or {}).get("message")
            if isinstance(commit, dict)
            else None
        )
        if (
            not isinstance(author, dict)
            or author.get("login") != bot_login
            or author.get("id") != bot_id
            or author.get("type") != "Bot"
            or not isinstance(parents, list)
            or len(parents) != 1
            or (parents[0] or {}).get("sha") != record.get("baseSha")
            or message != repair_commit_message(record, plan)
        ):
            raise ProtectedRemediationError(
                "protected repair ref does not resolve to exact App-authored commit"
            )
        if _contents_bytes(read_api, str(plan["targetPath"]), commit_sha) != repaired:
            raise ProtectedRemediationError(
                "protected repair ref bytes differ from deterministic output"
            )
    except ProtectedRemediationError:
        if created_ref:
            _delete_exact_generated_branch(read_api, write_api, branch, commit_sha)
        raise
    return commit_sha, created_ref


def _find_pull_for_branch(api: GitHubApi, branch: str) -> dict[str, Any] | None:
    matches = _pulls_for_branch(api, branch)
    return matches[0] if matches else None


def _validate_created_repair_rollback_identity(
    pr: Any,
    *,
    number: int,
    branch: str,
    head_sha: str,
    title: str,
    body: str,
    bot_login: str,
    bot_id: int,
    expected_state: str,
    expected_base_ref: str = EXPECTED_BASE_BRANCH,
    expected_base_sha: str | None = None,
) -> None:
    if expected_state not in {"open", "closed"}:
        raise ProtectedRemediationError("created protected repair rollback state is invalid")
    if (
        expected_base_ref != EXPECTED_BASE_BRANCH
        and STAGING_BASE_RE.fullmatch(expected_base_ref) is None
    ):
        raise ProtectedRemediationError("created protected repair rollback base escaped authority")
    if expected_base_sha is not None:
        expected_base_sha = _require_sha(
            expected_base_sha,
            "created protected repair rollback base SHA",
        )
    if not isinstance(pr, dict):
        raise ProtectedRemediationError("created protected repair rollback PR is malformed")
    user = pr.get("user") or {}
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        pr.get("number") != number
        or pr.get("state") != expected_state
        or pr.get("draft") is not False
        or pr.get("title") != title
        or pr.get("body") != body
        or user.get("login") != bot_login
        or user.get("id") != bot_id
        or user.get("type") != "Bot"
        or head.get("ref") != branch
        or _require_sha(head.get("sha"), "created protected repair rollback head SHA") != head_sha
        or (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != expected_base_ref
        or (
            expected_base_sha is not None
            and _require_sha(
                base.get("sha"),
                "created protected repair rollback observed base SHA",
            )
            != expected_base_sha
        )
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ProtectedRemediationError(
            "created protected repair PR could not be proven exact for rollback"
        )


def _rollback_created_repair_pr(
    read_api: GitHubApi,
    write_api: GitHubApi,
    *,
    number: int,
    branch: str,
    head_sha: str,
    title: str,
    body: str,
    bot_login: str,
    bot_id: int,
    expected_base_ref: str = EXPECTED_BASE_BRANCH,
    expected_base_sha: str | None = None,
) -> None:
    _validate_created_repair_rollback_identity(
        read_api.get(f"/pulls/{number}"),
        number=number,
        branch=branch,
        head_sha=head_sha,
        title=title,
        body=body,
        bot_login=bot_login,
        bot_id=bot_id,
        expected_state="open",
        expected_base_ref=expected_base_ref,
        expected_base_sha=expected_base_sha,
    )
    closed = write_api.patch(f"/pulls/{number}", {"state": "closed"})
    if (
        not isinstance(closed, dict)
        or closed.get("number") != number
        or closed.get("state") != "closed"
    ):
        raise ProtectedRemediationError(
            "GitHub did not acknowledge created protected repair PR rollback"
        )
    _validate_created_repair_rollback_identity(
        read_api.get(f"/pulls/{number}"),
        number=number,
        branch=branch,
        head_sha=head_sha,
        title=title,
        body=body,
        bot_login=bot_login,
        bot_id=bot_id,
        expected_state="closed",
        expected_base_ref=expected_base_ref,
        expected_base_sha=expected_base_sha,
    )
    if expected_base_ref != EXPECTED_BASE_BRANCH:
        if expected_base_sha is None:
            raise ProtectedRemediationError(
                "staged protected repair rollback requires exact base SHA"
            )
        _delete_exact_staging_base(
            read_api,
            write_api,
            expected_base_ref,
            expected_base_sha,
        )
    _delete_exact_generated_branch(read_api, write_api, branch, head_sha)


def _ensure_repair_pr(
    read_api: GitHubApi,
    write_api: GitHubApi,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    repaired: bytes,
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any]:
    branch = branch_name(record)
    commit_sha, created_ref = _create_repair_commit(
        read_api,
        write_api,
        record,
        plan,
        repaired,
        bot_login=bot_login,
        bot_id=bot_id,
        control_sha=control_sha,
    )
    existing = _find_pull_for_branch(read_api, branch)
    created_number: int | None = None
    created_title = f"security: remediate protected CodeQL alert #{record['alertNumber']}"
    created_body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + marker(record, plan, head_sha=commit_sha)
    )

    if existing is not None:
        if existing.get("state") != "open":
            raise ProtectedRemediationError(
                "protected repair branch is already bound to a closed PR"
            )
        pr = read_api.get(
            f"/pulls/{_require_positive_int(existing.get('number'), 'repair PR number')}"
        )
        recovered = _recover_repair_publication(
            read_api,
            write_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )
        if recovered is None:
            raise ProtectedRemediationError("staged protected repair became stale during recovery")
        pr = recovered
    else:
        try:
            require_current_control_revision(read_api, control_sha)
            staging_base = _ensure_staging_base_ref(read_api, write_api, record)
            require_current_control_revision(read_api, control_sha)
        except ProtectedRemediationError:
            staging_base = _staging_base_name(record)
            retained_staging = _staging_ref_sha(read_api, staging_base)
            if retained_staging is not None:
                _delete_exact_staging_base(
                    read_api,
                    write_api,
                    staging_base,
                    _require_sha(record.get("baseSha"), "failed publication staging base SHA"),
                )
            if created_ref:
                _delete_exact_generated_branch(read_api, write_api, branch, commit_sha)
            raise

        # An exact generated ref that predates this run with no pull request is a retained
        # ambiguous/crash artifact. Never replay the non-idempotent PR creation POST in the
        # same reconciliation. Prove both refs unclaimed, remove only the exact owned refs,
        # and let a later accepted-main run begin from a clean publication boundary.
        if not created_ref:
            retained_staging = _staging_ref_sha(read_api, staging_base)
            if retained_staging is not None:
                _delete_exact_staging_base(
                    read_api,
                    write_api,
                    staging_base,
                    _require_sha(record.get("baseSha"), "orphan publication staging base SHA"),
                )
            _delete_exact_generated_branch(read_api, write_api, branch, commit_sha)
            raise ProtectedRemediationError(
                "retained protected repair refs had no durable PR; exact refs were pruned "
                "without replaying PR creation"
            )

        create_error: ProtectedRemediationError | None = None
        created: Any = None
        try:
            created = write_api.post(
                "/pulls",
                {
                    "title": created_title,
                    "head": branch,
                    "base": staging_base,
                    "body": created_body,
                    "draft": False,
                },
            )
        except ProtectedRemediationError as exc:
            create_error = exc

        if create_error is not None:
            converged = _find_pull_for_branch(read_api, branch)
            if converged is None:
                raise ProtectedRemediationError(
                    "protected repair PR creation failed ambiguously after App submission; "
                    "retaining exact staging and generated refs for later read-back"
                ) from create_error
            created_number = _require_positive_int(
                converged.get("number"),
                "read-back created repair PR number",
            )
            _validate_repair_publication_identity(
                read_api.get(f"/pulls/{created_number}"),
                number=created_number,
                branch=branch,
                head_sha=commit_sha,
                base_ref=staging_base,
                base_sha=_require_sha(record.get("baseSha"), "repair publication base SHA"),
                title=created_title,
                body=created_body,
                bot_login=bot_login,
                bot_id=bot_id,
            )
        else:
            created_number = _require_positive_int(
                (created or {}).get("number"),
                "created repair PR number",
            )
        try:
            pr = read_api.get(f"/pulls/{created_number}")
            _validate_repair_publication_identity(
                pr,
                number=created_number,
                branch=branch,
                head_sha=commit_sha,
                base_ref=staging_base,
                base_sha=_require_sha(record.get("baseSha"), "repair publication base SHA"),
                title=created_title,
                body=created_body,
                bot_login=bot_login,
                bot_id=bot_id,
            )
            require_current_control_revision(read_api, control_sha)
        except ProtectedRemediationError:
            _rollback_created_repair_pr(
                read_api,
                write_api,
                number=created_number,
                branch=branch,
                head_sha=commit_sha,
                title=created_title,
                body=created_body,
                bot_login=bot_login,
                bot_id=bot_id,
                expected_base_ref=staging_base,
                expected_base_sha=_require_sha(
                    record.get("baseSha"),
                    "repair rollback staging base SHA",
                ),
            )
            raise

        pr = _retarget_staged_repair_pr(
            read_api,
            write_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )

    try:
        observed = validate_generated_pr(
            read_api,
            pr,
            expected_bot_login=bot_login,
            expected_bot_id=bot_id,
        )
        if observed["headSha"] != commit_sha:
            raise ProtectedRemediationError(
                "protected repair PR head differs from exact repair commit"
            )
    except ProtectedRemediationError:
        if created_number is not None:
            _rollback_created_repair_pr(
                read_api,
                write_api,
                number=created_number,
                branch=branch,
                head_sha=commit_sha,
                title=created_title,
                body=created_body,
                bot_login=bot_login,
                bot_id=bot_id,
            )
        raise
    return dict(pr)


def _open_generated_repairs(api: GitHubApi, *, bot_login: str, bot_id: int) -> list[dict[str, Any]]:
    pulls = api.list_all("/pulls?state=open&sort=created&direction=asc", max_pages=1)
    rows = [pr for pr in pulls if _generated_bot_pull(pr, login=bot_login, user_id=bot_id)]
    if len(rows) > 1:
        raise ProtectedRemediationError("multiple active protected repair PRs are not permitted")
    return rows


def _generated_repair_is_stale(
    api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
) -> bool:
    if not _generated_bot_pull(pr, login=bot_login, user_id=bot_id):
        raise ProtectedRemediationError("stale repair cleanup subject is not the exact author App")
    if pr.get("state") != "open" or pr.get("draft") is not False:
        raise ProtectedRemediationError("stale repair cleanup subject is not an open non-draft PR")
    number = _require_positive_int(pr.get("number"), "stale protected repair PR number")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != EXPECTED_BASE_BRANCH
    ):
        raise ProtectedRemediationError("stale repair cleanup repository/base identity drifted")
    head_sha = _require_sha(head.get("sha"), "stale protected repair head SHA")
    base_sha = _require_sha(base.get("sha"), "stale protected repair base SHA")
    current_main = _current_main(api)

    metadata = parse_marker(pr.get("body"))
    if metadata is None or set(metadata) != {
        "version",
        "base",
        "head",
        "routeRecord",
        "repairPlan",
    }:
        raise ProtectedRemediationError("stale repair cleanup marker is missing or malformed")
    marker_base = _require_sha(
        metadata.get("base"),
        "stale protected repair marker base SHA",
    )
    if metadata.get("version") != 1 or metadata.get("head") != head_sha:
        raise ProtectedRemediationError("stale repair cleanup marker identity drifted")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("stale repair cleanup marker evidence is malformed")
    try:
        strategy = validate_route_record(record, main_sha=marker_base)
        canonical_plan(plan)
        expected_branch = branch_name(record)
    except (RoutingPolicyError, ProtectedRemediationError) as exc:
        raise ProtectedRemediationError(
            "stale repair cleanup marker evidence is not canonical"
        ) from exc
    if (
        plan.get("baseSha") != marker_base
        or plan.get("targetPath") != strategy.path
        or plan.get("changedFiles") != [strategy.path]
        or plan.get("maxChangedFiles") != MAX_CHANGED_FILES
        or head.get("ref") != expected_branch
    ):
        raise ProtectedRemediationError("stale repair cleanup marker authority drifted")

    expected_title = f"security: remediate protected CodeQL alert #{record['alertNumber']}"
    expected_body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + marker(record, plan, head_sha=head_sha)
    )
    if pr.get("title") != expected_title or pr.get("body") != expected_body:
        raise ProtectedRemediationError("stale repair cleanup presentation identity drifted")

    base_source = _contents_bytes(api, strategy.path, marker_base)
    repaired = revalidate_repair_plan(plan, base_source, record, main_sha=marker_base)
    if _contents_bytes(api, strategy.path, head_sha) != repaired:
        raise ProtectedRemediationError(
            "stale repair cleanup head bytes differ from deterministic output"
        )

    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    if (
        len(files) != 1
        or not isinstance(files[0], dict)
        or files[0].get("filename") != strategy.path
        or files[0].get("status") != "modified"
    ):
        raise ProtectedRemediationError(
            "stale repair cleanup diff escaped exact one-file authority"
        )

    commit = api.get(f"/commits/{head_sha}")
    author = (commit or {}).get("author") if isinstance(commit, dict) else None
    parents = (commit or {}).get("parents") if isinstance(commit, dict) else None
    message = (
        ((commit or {}).get("commit") or {}).get("message") if isinstance(commit, dict) else None
    )
    if (
        not isinstance(author, dict)
        or author.get("login") != bot_login
        or author.get("id") != bot_id
        or author.get("type") != "Bot"
        or not isinstance(parents, list)
        or len(parents) != 1
        or (parents[0] or {}).get("sha") != marker_base
        or message != repair_commit_message(record, plan)
    ):
        raise ProtectedRemediationError(
            "stale repair cleanup head is not the exact App-authored repair commit"
        )

    return current_main != base_sha or marker_base != base_sha


def _close_stale_generated_repair(
    read_api: GitHubApi,
    write_api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any]:
    number = _require_positive_int(pr.get("number"), "stale protected repair PR number")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    branch = head.get("ref")
    title = pr.get("title")
    body = pr.get("body")
    if not isinstance(branch, str) or not isinstance(title, str) or not isinstance(body, str):
        raise ProtectedRemediationError("stale protected repair cleanup identity is malformed")
    head_sha = _require_sha(head.get("sha"), "stale protected repair head SHA")
    base_sha = _require_sha(base.get("sha"), "stale protected repair base SHA")

    require_current_control_revision(read_api, control_sha)
    fresh = read_api.get(f"/pulls/{number}")
    _validate_created_repair_rollback_identity(
        fresh,
        number=number,
        branch=branch,
        head_sha=head_sha,
        title=title,
        body=body,
        bot_login=bot_login,
        bot_id=bot_id,
        expected_state="open",
        expected_base_ref=expected_base_ref,
        expected_base_sha=expected_base_sha,
    )
    if not _generated_repair_is_stale(
        read_api,
        fresh,
        bot_login=bot_login,
        bot_id=bot_id,
    ):
        raise ProtectedRemediationError("protected repair is no longer stale at cleanup boundary")

    require_current_control_revision(read_api, control_sha)
    close_error: ProtectedRemediationError | None = None
    try:
        result = write_api.patch(f"/pulls/{number}", {"state": "closed"})
    except ProtectedRemediationError as exc:
        result = None
        close_error = exc

    closed = read_api.get(f"/pulls/{number}")
    try:
        _validate_created_repair_rollback_identity(
            closed,
            number=number,
            branch=branch,
            head_sha=head_sha,
            title=title,
            body=body,
            bot_login=bot_login,
            bot_id=bot_id,
            expected_state="closed",
        )
    except ProtectedRemediationError as state_exc:
        if close_error is not None:
            raise ProtectedRemediationError(
                "stale protected repair closure outcome is not durably closed"
            ) from close_error
        if (
            not isinstance(result, dict)
            or result.get("number") != number
            or result.get("state") != "closed"
        ):
            raise ProtectedRemediationError(
                "GitHub did not acknowledge stale protected PR closure"
            ) from state_exc
        raise

    metadata = parse_marker(body)
    if metadata is None or not isinstance(metadata.get("routeRecord"), dict):
        raise ProtectedRemediationError(
            "stale protected repair marker disappeared before ref cleanup"
        )
    retained_staging = _staging_base_name(metadata["routeRecord"])
    retained_staging_sha = _staging_ref_sha(read_api, retained_staging)
    if retained_staging_sha is not None:
        marker_base = _require_sha(
            metadata.get("base"),
            "stale protected repair retained staging base SHA",
        )
        if retained_staging_sha != marker_base:
            raise ProtectedRemediationError(
                "retained protected repair staging ref changed before stale cleanup"
            )
        _delete_exact_staging_base(
            read_api,
            write_api,
            retained_staging,
            marker_base,
        )
    _delete_exact_generated_branch(read_api, write_api, branch, head_sha)
    return {
        "decision": "stale-protected-repair-closed",
        "pr": number,
        "headSha": head_sha,
        "baseSha": base_sha,
    }


def _terminal_comment_body(certificate: Mapping[str, Any]) -> str:
    return (
        TERMINAL_COMMENT_PREFIX
        + json.dumps(dict(certificate), separators=(",", ":"), sort_keys=True)
        + TERMINAL_COMMENT_SUFFIX
    )


def _parse_terminal_comment(body: Any) -> dict[str, Any] | None:
    if (
        not isinstance(body, str)
        or not body.startswith(TERMINAL_COMMENT_PREFIX)
        or not body.endswith(TERMINAL_COMMENT_SUFFIX)
        or "\n" in body
        or "\r" in body
    ):
        return None
    raw = body[len(TERMINAL_COMMENT_PREFIX) : -len(TERMINAL_COMMENT_SUFFIX)]
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or _terminal_comment_body(value) != body:
        return None
    return value


def _terminal_comments(
    api: Any,
    number: int,
) -> list[dict[str, Any]]:
    rows = api.list_all(f"/issues/{number}/comments", max_pages=4)
    certificates: list[dict[str, Any]] = []
    for row in rows:
        actor = row.get("user") or {}
        body = row.get("body")
        if (
            actor.get("login") != TERMINAL_CERTIFICATE_BOT_LOGIN
            or actor.get("id") != TERMINAL_CERTIFICATE_BOT_ID
            or actor.get("type") != "Bot"
            or not isinstance(body, str)
            or not body.startswith(TERMINAL_COMMENT_PREFIX)
        ):
            continue
        certificate = _parse_terminal_comment(body)
        created_at = row.get("created_at")
        if (
            certificate is None
            or not isinstance(created_at, str)
            or not created_at
            or row.get("updated_at") != created_at
        ):
            raise ProtectedRemediationError(
                "protected remediation terminal certificate is malformed or edited"
            )
        certificates.append(certificate)
    if len(certificates) > 1:
        raise ProtectedRemediationError(
            "protected remediation has ambiguous terminal closure certificates"
        )
    return certificates


def _pending_merged_repair(
    api: Any,
    *,
    current_main: str,
    bot_login: str,
    bot_id: int,
) -> dict[str, Any] | None:
    current_main = _require_sha(current_main, "terminal current main SHA")
    rows = api.list_all(f"/commits/{current_main}/pulls", max_pages=1)
    matches = [
        row
        for row in rows
        if _generated_bot_pull(row, login=bot_login, user_id=bot_id)
        and row.get("state") == "closed"
        and row.get("merged_at") is not None
    ]
    if len(matches) > 1:
        numbers = sorted(
            _require_positive_int(row.get("number"), "current-main protected repair PR number")
            for row in matches
        )
        raise ProtectedRemediationError(
            f"current main maps to multiple merged protected repairs: {numbers}"
        )
    if not matches:
        return None

    row = matches[0]
    number = _require_positive_int(
        row.get("number"),
        "current-main protected repair PR number",
    )
    if (
        _require_sha(
            row.get("merge_commit_sha"),
            "current-main protected repair merge SHA",
        )
        != current_main
    ):
        raise ProtectedRemediationError(
            "current-main protected repair association has mismatched merge SHA"
        )

    live = api.get(f"/pulls/{number}")
    if not isinstance(live, dict):
        raise ProtectedRemediationError("merged protected repair lookup returned malformed data")
    return live


def _validate_merged_repair(
    api: Any,
    pr: Mapping[str, Any],
    *,
    expected_bot_login: str,
    expected_bot_id: int,
) -> dict[str, Any]:
    bot_login, bot_id = _require_author_identity(expected_bot_login, expected_bot_id)
    if (
        not isinstance(pr, Mapping)
        or pr.get("state") != "closed"
        or pr.get("merged_at") is None
        or pr.get("draft") is not False
    ):
        raise ProtectedRemediationError(
            "terminal protected repair must be a merged non-draft pull request"
        )
    number = _require_positive_int(pr.get("number"), "terminal protected repair PR number")
    user = pr.get("user") or {}
    merged_by = pr.get("merged_by") or {}
    if (
        user.get("login") != bot_login
        or user.get("id") != bot_id
        or user.get("type") != "Bot"
        or merged_by.get("login") != bot_login
        or merged_by.get("id") != bot_id
        or merged_by.get("type") != "Bot"
    ):
        raise ProtectedRemediationError(
            "terminal protected repair was not authored and merged by the exact author App"
        )

    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != EXPECTED_BASE_BRANCH
    ):
        raise ProtectedRemediationError(
            "terminal protected repair repository/base identity drifted"
        )
    branch = head.get("ref")
    if not isinstance(branch, str) or BRANCH_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError(
            "terminal protected repair branch is outside reviewed grammar"
        )
    head_sha = _require_sha(head.get("sha"), "terminal protected repair head SHA")
    base_sha = _require_sha(base.get("sha"), "terminal protected repair base SHA")
    merge_sha = _require_sha(pr.get("merge_commit_sha"), "terminal protected repair merge SHA")

    metadata = parse_marker(pr.get("body"))
    if metadata is None or set(metadata) != {
        "version",
        "base",
        "head",
        "routeRecord",
        "repairPlan",
    }:
        raise ProtectedRemediationError("terminal protected repair marker is missing or malformed")
    if (
        metadata.get("version") != 1
        or metadata.get("base") != base_sha
        or metadata.get("head") != head_sha
    ):
        raise ProtectedRemediationError("terminal protected repair marker subject drifted")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("terminal protected repair marker evidence is malformed")
    strategy = validate_route_record(record, main_sha=base_sha)
    canonical_plan(plan)
    expected_title = f"security: remediate protected CodeQL alert #{record['alertNumber']}"
    expected_body = (
        "Automated independent protected-control-plane remediation. "
        "The authoring App cannot publish Trusted PR Gate.\n\n"
        + marker(record, plan, head_sha=head_sha)
    )
    if pr.get("title") != expected_title or pr.get("body") != expected_body:
        raise ProtectedRemediationError("terminal protected repair presentation identity drifted")
    if (
        plan.get("baseSha") != base_sha
        or plan.get("targetPath") != strategy.path
        or plan.get("changedFiles") != [strategy.path]
        or plan.get("maxChangedFiles") != MAX_CHANGED_FILES
        or branch != branch_name(record)
    ):
        raise ProtectedRemediationError("terminal protected repair plan authority drifted")

    base_source = _contents_bytes(api, strategy.path, base_sha)
    repaired = revalidate_repair_plan(plan, base_source, record, main_sha=base_sha)
    if _contents_bytes(api, strategy.path, head_sha) != repaired:
        raise ProtectedRemediationError(
            "terminal protected repair head bytes differ from deterministic output"
        )

    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    if (
        len(files) != 1
        or files[0].get("filename") != strategy.path
        or files[0].get("status") != "modified"
        or files[0].get("previous_filename") is not None
    ):
        raise ProtectedRemediationError(
            "terminal protected repair diff escaped exact one-file modification authority"
        )

    head_commit = api.get(f"/commits/{head_sha}")
    head_author = (head_commit or {}).get("author") if isinstance(head_commit, dict) else None
    head_parents = (head_commit or {}).get("parents") if isinstance(head_commit, dict) else None
    if (
        not isinstance(head_commit, dict)
        or not isinstance(head_author, dict)
        or head_author.get("login") != bot_login
        or head_author.get("id") != bot_id
        or head_author.get("type") != "Bot"
        or not isinstance(head_parents, list)
        or len(head_parents) != 1
        or (head_parents[0] or {}).get("sha") != base_sha
        or ((head_commit.get("commit") or {}).get("message")) != repair_commit_message(record, plan)
    ):
        raise ProtectedRemediationError(
            "terminal protected repair head lacks exact App-authored provenance"
        )

    head_git_commit = api.get(f"/git/commits/{head_sha}")
    merge_commit = api.get(f"/git/commits/{merge_sha}")
    merge_parents = (merge_commit or {}).get("parents") if isinstance(merge_commit, dict) else None
    verification = (
        (merge_commit or {}).get("verification") if isinstance(merge_commit, dict) else None
    )
    if (
        not isinstance(head_git_commit, dict)
        or not isinstance(merge_commit, dict)
        or _require_sha(merge_commit.get("sha"), "terminal protected merge commit SHA") != merge_sha
        or not isinstance(merge_parents, list)
        or [((parent or {}).get("sha")) for parent in merge_parents] != [base_sha, head_sha]
        or ((merge_commit.get("tree") or {}).get("sha"))
        != ((head_git_commit.get("tree") or {}).get("sha"))
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        raise ProtectedRemediationError(
            "terminal protected repair merge topology/tree/signature drifted"
        )

    return {
        "number": number,
        "baseSha": base_sha,
        "headSha": head_sha,
        "mergeSha": merge_sha,
        "alertNumber": _require_positive_int(
            record.get("alertNumber"),
            "terminal protected repair alert number",
        ),
        "rule": str(record.get("rule")),
        "path": strategy.path,
        "recordDigest": _require_digest(
            record.get("recordDigest"),
            "terminal protected repair route digest",
        ),
        "planDigest": _require_digest(
            plan.get("planDigest"),
            "terminal protected repair plan digest",
        ),
    }


def _require_exact_merge_main(merge_sha: str, current_main: str) -> None:
    merge_sha = _require_sha(merge_sha, "terminal protected repair merge SHA")
    current_main = _require_sha(current_main, "terminal current main SHA")
    if merge_sha != current_main:
        raise ProtectedRemediationError("terminal protected repair merge is not exact current main")


def _terminal_trusted_gate_evidence(
    api: Any,
    evidence: Mapping[str, Any],
) -> dict[str, int | str]:
    number = _require_positive_int(evidence.get("number"), "terminal protected repair PR number")
    head_sha = _require_sha(evidence.get("headSha"), "terminal protected repair head SHA")
    base_sha = _require_sha(evidence.get("baseSha"), "terminal protected repair base SHA")
    rows = api.list_all(
        f"/commits/{head_sha}/statuses",
        max_pages=TERMINAL_STATUS_PAGES,
    )
    matches: list[dict[str, Any]] = []
    for row in rows:
        creator = row.get("creator") or {}
        if (
            row.get("context") == TRUSTED_STATUS_CONTEXT
            and creator.get("login") == TRUSTED_STATUS_BOT_LOGIN
            and creator.get("id") == TRUSTED_STATUS_BOT_ID
            and creator.get("type") == "Bot"
        ):
            _require_positive_int(row.get("id"), "terminal trusted status id")
            matches.append(row)
    if not matches:
        raise ProtectedRemediationError(
            "terminal protected repair lacks dedicated-App trusted status"
        )
    latest = max(matches, key=lambda row: int(row["id"]))
    if latest.get("state") != "success" or latest.get("description") != TRUSTED_STATUS_DESCRIPTION:
        raise ProtectedRemediationError(
            "terminal protected repair latest dedicated-App trusted status is not green"
        )
    target_url = latest.get("target_url")
    if not isinstance(target_url, str):
        raise ProtectedRemediationError("terminal protected repair trusted target URL is missing")
    match = TARGET_URL_RE.fullmatch(target_url)
    if (
        match is None
        or int(match.group("pr")) != number
        or match.group("base") != base_sha
        or match.group("head") != head_sha
    ):
        raise ProtectedRemediationError(
            "terminal protected repair trusted status is not exact-subject-bound"
        )
    prospective_sha = _require_sha(
        match.group("merge"),
        "terminal protected repair prospective merge SHA",
    )
    prospective = api.get(f"/git/commits/{prospective_sha}")
    prospective_parents = (
        (prospective or {}).get("parents") if isinstance(prospective, dict) else None
    )
    head_commit = api.get(f"/git/commits/{head_sha}")
    if (
        not isinstance(prospective, dict)
        or not isinstance(head_commit, dict)
        or _require_sha(prospective.get("sha"), "terminal trusted prospective merge SHA")
        != prospective_sha
        or not isinstance(prospective_parents, list)
        or [((parent or {}).get("sha")) for parent in prospective_parents] != [base_sha, head_sha]
        or ((prospective.get("tree") or {}).get("sha"))
        != ((head_commit.get("tree") or {}).get("sha"))
    ):
        raise ProtectedRemediationError(
            "terminal protected repair trusted prospective merge evidence drifted"
        )
    run_id = int(match.group("run_id"))
    run = api.get(f"/actions/runs/{run_id}")
    repository = (run or {}).get("repository") if isinstance(run, dict) else None
    head_repository = (run or {}).get("head_repository") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or _require_positive_int(run.get("id"), "terminal trusted gate run id") != run_id
        or _require_positive_int(
            run.get("workflow_id"),
            "terminal trusted gate workflow id",
        )
        != EXPECTED_GATE_WORKFLOW_ID
        or _require_positive_int(
            run.get("run_attempt"),
            "terminal trusted gate run attempt",
        )
        != 1
        or run.get("name") != EXPECTED_GATE_WORKFLOW_NAME
        or run.get("path") != EXPECTED_GATE_WORKFLOW_PATH
        or run.get("event") not in EXPECTED_GATE_EVENTS
        or run.get("head_branch") != EXPECTED_BASE_BRANCH
        or _require_sha(run.get("head_sha"), "terminal trusted gate head SHA") != base_sha
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        raise ProtectedRemediationError(
            "terminal protected repair trusted run is not exact accepted-main evidence"
        )
    return {
        "statusId": int(latest["id"]),
        "runId": run_id,
        "prospectiveMergeSha": prospective_sha,
    }


def _terminal_workflow_evidence(
    api: Any,
    *,
    workflow: str,
    workflow_id: int,
    workflow_name: str,
    workflow_path: str,
    subject_sha: str,
    bot_login: str,
    bot_id: int,
    required_job: str | None = None,
) -> dict[str, Any] | None:
    subject_sha = _require_sha(subject_sha, "terminal workflow subject SHA")
    encoded_workflow = urllib.parse.quote(workflow, safe="")
    encoded_sha = urllib.parse.quote(subject_sha, safe="")
    payload = api.get(
        f"/actions/workflows/{encoded_workflow}/runs"
        f"?head_sha={encoded_sha}&event=push&per_page={TERMINAL_RUN_PAGE_SIZE}&page=1"
    )
    runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
    total = payload.get("total_count") if isinstance(payload, dict) else None
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
        or total > TERMINAL_RUN_PAGE_SIZE
        or not isinstance(runs, list)
        or any(not isinstance(row, dict) for row in runs)
        or total != len(runs)
    ):
        raise ProtectedRemediationError("terminal workflow run evidence is malformed or unbounded")
    if not runs:
        return None
    if len(runs) != 1:
        raise ProtectedRemediationError("terminal workflow run evidence is ambiguous")
    run = runs[0]
    actor = run.get("actor") or {}
    triggering_actor = run.get("triggering_actor") or {}
    repository = run.get("repository") or {}
    head_repository = run.get("head_repository") or {}
    if (
        run.get("workflow_id") != workflow_id
        or run.get("name") != workflow_name
        or run.get("path") != workflow_path
        or run.get("event") != "push"
        or run.get("head_branch") != EXPECTED_BASE_BRANCH
        or run.get("head_sha") != subject_sha
        or run.get("run_attempt") != 1
        or repository.get("full_name") != EXPECTED_REPOSITORY
        or head_repository.get("full_name") != EXPECTED_REPOSITORY
        or actor.get("login") != bot_login
        or actor.get("id") != bot_id
        or actor.get("type") != "Bot"
        or triggering_actor.get("login") != bot_login
        or triggering_actor.get("id") != bot_id
        or triggering_actor.get("type") != "Bot"
    ):
        raise ProtectedRemediationError(
            "terminal workflow run is not exact independent-App push evidence"
        )
    status = run.get("status")
    if status in {"queued", "in_progress", "waiting", "pending", "requested"}:
        return {"run": run, "requiredJob": None}
    if status != "completed" or run.get("conclusion") != "success":
        raise ProtectedRemediationError(
            f"terminal workflow completed non-successfully: {run.get('conclusion')}"
        )

    required: dict[str, Any] | None = None
    if required_job is not None:
        run_id = _require_positive_int(run.get("id"), "terminal workflow run id")
        jobs_payload = api.get(
            f"/actions/runs/{run_id}/jobs?filter=latest&per_page={TERMINAL_JOB_LIMIT}"
        )
        jobs = jobs_payload.get("jobs") if isinstance(jobs_payload, dict) else None
        jobs_total = jobs_payload.get("total_count") if isinstance(jobs_payload, dict) else None
        if (
            not isinstance(jobs_total, int)
            or isinstance(jobs_total, bool)
            or jobs_total < 0
            or jobs_total > TERMINAL_JOB_LIMIT
            or not isinstance(jobs, list)
            or any(not isinstance(job, dict) for job in jobs)
            or jobs_total != len(jobs)
        ):
            raise ProtectedRemediationError(
                "terminal workflow job evidence is malformed or unbounded"
            )
        matches = [job for job in jobs if job.get("name") == required_job]
        if len(matches) != 1:
            raise ProtectedRemediationError(
                "terminal workflow required-gate evidence is missing or ambiguous"
            )
        required = matches[0]
        _require_positive_int(required.get("id"), "terminal workflow required-gate job id")
        if required.get("status") != "completed" or required.get("conclusion") != "success":
            raise ProtectedRemediationError(
                "terminal workflow required gate did not complete successfully"
            )
    return {"run": run, "requiredJob": required}


def _terminal_alert_is_fixed(
    api: Any,
    evidence: Mapping[str, Any],
) -> bool:
    alert_number = _require_positive_int(
        evidence.get("alertNumber"),
        "terminal protected repair alert number",
    )
    alert = api.get(f"/code-scanning/alerts/{alert_number}")
    if not isinstance(alert, dict):
        raise ProtectedRemediationError("terminal protected CodeQL alert is malformed")
    if (
        (alert.get("tool") or {}).get("name") != "CodeQL"
        or (alert.get("rule") or {}).get("id") != evidence.get("rule")
        or ((alert.get("most_recent_instance") or {}).get("location") or {}).get("path")
        != evidence.get("path")
    ):
        raise ProtectedRemediationError("terminal protected CodeQL alert identity drifted")
    state = alert.get("state")
    if state == "fixed":
        return True
    if state == "open":
        return False
    raise ProtectedRemediationError(
        f"terminal protected CodeQL alert has unsupported state: {state}"
    )


def _terminal_certificate(
    evidence: Mapping[str, Any],
    *,
    trusted: Mapping[str, Any],
    ci: Mapping[str, Any],
    codeql: Mapping[str, Any],
    observed_main: str,
) -> dict[str, Any]:
    ci_run = ci.get("run") or {}
    ci_job = ci.get("requiredJob") or {}
    codeql_run = codeql.get("run") or {}
    return {
        "schemaVersion": TERMINAL_SCHEMA_VERSION,
        "kind": "protected-security-remediation-terminal",
        "pr": _require_positive_int(evidence.get("number"), "terminal certificate PR number"),
        "alertNumber": _require_positive_int(
            evidence.get("alertNumber"),
            "terminal certificate alert number",
        ),
        "rule": str(evidence.get("rule")),
        "path": str(evidence.get("path")),
        "baseSha": _require_sha(evidence.get("baseSha"), "terminal certificate base SHA"),
        "headSha": _require_sha(evidence.get("headSha"), "terminal certificate head SHA"),
        "mergeSha": _require_sha(evidence.get("mergeSha"), "terminal certificate merge SHA"),
        "observedMainSha": _require_sha(observed_main, "terminal certificate observed main SHA"),
        "routeRecordDigest": _require_digest(
            evidence.get("recordDigest"),
            "terminal certificate route digest",
        ),
        "repairPlanDigest": _require_digest(
            evidence.get("planDigest"),
            "terminal certificate plan digest",
        ),
        "trustedStatusId": _require_positive_int(
            trusted.get("statusId"),
            "terminal certificate trusted status id",
        ),
        "trustedRunId": _require_positive_int(
            trusted.get("runId"),
            "terminal certificate trusted run id",
        ),
        "trustedProspectiveMergeSha": _require_sha(
            trusted.get("prospectiveMergeSha"),
            "terminal certificate trusted prospective merge SHA",
        ),
        "ciRunId": _require_positive_int(
            ci_run.get("id"),
            "terminal certificate CI run id",
        ),
        "ciRequiredJobId": _require_positive_int(
            ci_job.get("id"),
            "terminal certificate CI required-gate job id",
        ),
        "codeqlRunId": _require_positive_int(
            codeql_run.get("id"),
            "terminal certificate CodeQL run id",
        ),
        "result": "fixed",
    }


def _reconcile_terminal_closure(
    read_api: Any,
    certificate_api: Any,
    *,
    bot_login: str,
    bot_id: int,
    current_main: str,
) -> bool:
    pr = _pending_merged_repair(
        read_api,
        current_main=current_main,
        bot_login=bot_login,
        bot_id=bot_id,
    )
    if pr is None:
        return False
    evidence = _validate_merged_repair(
        read_api,
        pr,
        expected_bot_login=bot_login,
        expected_bot_id=bot_id,
    )
    _require_exact_merge_main(str(evidence["mergeSha"]), current_main)
    trusted = _terminal_trusted_gate_evidence(read_api, evidence)
    ci = _terminal_workflow_evidence(
        read_api,
        workflow=TERMINAL_CI_WORKFLOW,
        workflow_id=TERMINAL_CI_WORKFLOW_ID,
        workflow_name=TERMINAL_CI_WORKFLOW_NAME,
        workflow_path=TERMINAL_CI_WORKFLOW_PATH,
        subject_sha=str(evidence["mergeSha"]),
        bot_login=bot_login,
        bot_id=bot_id,
        required_job=TERMINAL_CI_REQUIRED_JOB,
    )
    codeql = _terminal_workflow_evidence(
        read_api,
        workflow=TERMINAL_CODEQL_WORKFLOW,
        workflow_id=TERMINAL_CODEQL_WORKFLOW_ID,
        workflow_name=TERMINAL_CODEQL_WORKFLOW_NAME,
        workflow_path=TERMINAL_CODEQL_WORKFLOW_PATH,
        subject_sha=str(evidence["mergeSha"]),
        bot_login=bot_login,
        bot_id=bot_id,
    )
    if (
        ci is None
        or codeql is None
        or (ci.get("run") or {}).get("status") != "completed"
        or (codeql.get("run") or {}).get("status") != "completed"
    ):
        print(
            json.dumps(
                {
                    "decision": "protected-terminal-closure-waiting",
                    "pr": evidence["number"],
                    "mergeSha": evidence["mergeSha"],
                    "reason": "exact independent-App push CI/CodeQL is not complete",
                },
                sort_keys=True,
            )
        )
        return True
    if not _terminal_alert_is_fixed(read_api, evidence):
        print(
            json.dumps(
                {
                    "decision": "protected-terminal-closure-waiting",
                    "pr": evidence["number"],
                    "mergeSha": evidence["mergeSha"],
                    "reason": "fresh exact-main CodeQL passed but the alert remains open",
                },
                sort_keys=True,
            )
        )
        return True
    if _current_main(read_api) != current_main:
        raise ProtectedRemediationError(
            "current main changed before protected terminal closure publication"
        )
    certificate = _terminal_certificate(
        evidence,
        trusted=trusted,
        ci=ci,
        codeql=codeql,
        observed_main=current_main,
    )
    number = int(evidence["number"])
    existing = _terminal_comments(read_api, number)
    if existing:
        if existing[0] != certificate:
            raise ProtectedRemediationError(
                "protected terminal certificate no longer matches exact live evidence"
            )
        if _current_main(read_api) != current_main:
            raise ProtectedRemediationError(
                "current main changed before protected terminal certificate revalidation"
            )
        print(
            json.dumps(
                {
                    "decision": "protected-repair-verified",
                    "pr": evidence["number"],
                    "mergeSha": evidence["mergeSha"],
                    "terminalCertificate": "durable-unedited-github-actions-comment",
                },
                sort_keys=True,
            )
        )
        return False
    body = _terminal_comment_body(certificate)
    created = certificate_api.post(f"/issues/{number}/comments", {"body": body})
    created_user = (created or {}).get("user") if isinstance(created, dict) else None
    comment_id = (created or {}).get("id") if isinstance(created, dict) else None
    if (
        not isinstance(created, dict)
        or created.get("body") != body
        or not isinstance(created_user, dict)
        or created_user.get("login") != TERMINAL_CERTIFICATE_BOT_LOGIN
        or created_user.get("id") != TERMINAL_CERTIFICATE_BOT_ID
        or created_user.get("type") != "Bot"
    ):
        raise ProtectedRemediationError(
            "GitHub did not acknowledge exact protected terminal certificate"
        )
    comment_id = _require_positive_int(comment_id, "protected terminal certificate comment id")
    durable = read_api.get(f"/issues/comments/{comment_id}")
    durable_created_at = durable.get("created_at") if isinstance(durable, dict) else None
    if (
        not isinstance(durable, dict)
        or durable.get("body") != body
        or (durable.get("user") or {}).get("login") != TERMINAL_CERTIFICATE_BOT_LOGIN
        or (durable.get("user") or {}).get("id") != TERMINAL_CERTIFICATE_BOT_ID
        or (durable.get("user") or {}).get("type") != "Bot"
        or not isinstance(durable_created_at, str)
        or not durable_created_at
        or durable.get("updated_at") != durable_created_at
    ):
        raise ProtectedRemediationError(
            "protected terminal certificate is not durable, exact, and unedited"
        )
    if _current_main(read_api) != current_main:
        raise ProtectedRemediationError(
            "current main changed after protected terminal closure publication"
        )
    print(
        json.dumps(
            {
                "decision": "protected-repair-verified",
                "pr": evidence["number"],
                "mergeSha": evidence["mergeSha"],
                "terminalCertificateCommentId": comment_id,
            },
            sort_keys=True,
        )
    )
    return True


def _protected_owner_review_provenance(
    live: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
) -> dict[str, Any]:
    return {
        "alertNumber": live.get("alertNumber"),
        "routeRecordDigest": live.get("routeRecordDigest"),
        "repairPlanDigest": live.get("planDigest"),
        "authorStrategy": live.get("authorStrategy"),
        "authorBotLogin": bot_login,
        "authorBotId": bot_id,
    }


def _protected_owner_review_subject(
    read_api: GitHubApi,
    *,
    pr_number: int,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any]:
    pr = read_api.get(f"/pulls/{pr_number}")
    live = validate_generated_pr(
        read_api,
        pr,
        expected_bot_login=bot_login,
        expected_bot_id=bot_id,
        config=load_config(),
    )
    require_current_control_revision(read_api, control_sha)
    if live["baseSha"] != control_sha:
        raise ProtectedRemediationError(
            "protected owner-review subject base is not the trusted control revision"
        )
    gate_status = require_automatic_trusted_gate(
        read_api,
        int(live["number"]),
        str(live["headSha"]),
        str(live["baseSha"]),
    )
    require_current_control_revision(read_api, control_sha)
    return {
        "prNumber": int(live["number"]),
        "headSha": str(live["headSha"]),
        "baseSha": str(live["baseSha"]),
        "gateStatus": gate_status,
        "provenance": _protected_owner_review_provenance(
            live,
            bot_login=bot_login,
            bot_id=bot_id,
        ),
    }


def _append_owner_review_outputs(
    path: str | None,
    *,
    approved: bool,
    pr_number: int | None,
) -> None:
    if path is None:
        return
    output = Path(path)
    if output.is_symlink():
        raise ProtectedRemediationError("protected owner-review output path must not be a symlink")
    with output.open("a", encoding="utf-8") as handle:
        handle.write(f"approved={'true' if approved else 'false'}\n")
        handle.write(f"lane={PROTECTED_SECURITY_LANE}\n")
        handle.write(f"pr_number={pr_number if pr_number is not None else ''}\n")


def publish_protected_owner_review(*, github_output: str | None) -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    bot_login, bot_id = _require_author_identity(
        os.environ.get("PROTECTED_REMEDIATION_BOT_LOGIN", ""),
        int(os.environ.get("PROTECTED_REMEDIATION_BOT_ID", "0") or "0"),
    )
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    control_sha = _required_control_sha()
    require_current_control_revision(read_api, control_sha)
    active = _open_generated_repairs(read_api, bot_login=bot_login, bot_id=bot_id)
    if not active:
        result = {"decision": "protected-security-owner-approval-no-candidate"}
        _append_owner_review_outputs(github_output, approved=False, pr_number=None)
        print(json.dumps(result, sort_keys=True))
        return result

    pr_number = _require_positive_int(active[0].get("number"), "protected owner-review PR number")
    try:
        _protected_owner_review_subject(
            read_api,
            pr_number=pr_number,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )
    except TrustedStatusError:
        result = {
            "decision": "protected-security-owner-approval-no-candidate",
            "pr": pr_number,
            "reason": "Trusted PR Gate not yet admissible",
        }
        _append_owner_review_outputs(github_output, approved=False, pr_number=None)
        print(json.dumps(result, sort_keys=True))
        return result

    def resolver() -> dict[str, Any]:
        return _protected_owner_review_subject(
            read_api,
            pr_number=pr_number,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )

    try:
        result = publish_exact_owner_approval(
            lane=PROTECTED_SECURITY_LANE,
            resolver=resolver,
        )
    except OwnerReviewPolicyBlock as exc:
        raise ProtectedRemediationError(str(exc)) from exc
    except OwnerReviewError as exc:
        raise ProtectedRemediationError(str(exc)) from exc
    _append_owner_review_outputs(github_output, approved=True, pr_number=pr_number)
    return result


def merge_approved_protected_repair(*, pr_number: int) -> dict[str, Any]:
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number < 1:
        raise ProtectedRemediationError("target protected repair PR number is invalid")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    bot_login, bot_id = _require_author_identity(
        os.environ.get("PROTECTED_REMEDIATION_BOT_LOGIN", ""),
        int(os.environ.get("PROTECTED_REMEDIATION_BOT_ID", "0") or "0"),
    )
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    write_api = GitHubApi(os.environ.get("PROTECTED_REMEDIATION_APP_TOKEN", ""), repository)
    control_sha = _required_control_sha()
    require_current_control_revision(read_api, control_sha)
    active = _open_generated_repairs(read_api, bot_login=bot_login, bot_id=bot_id)
    if len(active) != 1 or active[0].get("number") != pr_number:
        raise ProtectedRemediationError(
            "target protected repair is not the unique active App repair"
        )
    pr = read_api.get(f"/pulls/{pr_number}")
    result = _merge_repair(
        read_api,
        write_api,
        pr,
        bot_login=bot_login,
        bot_id=bot_id,
        control_sha=control_sha,
    )
    print(json.dumps(result, sort_keys=True))
    return result


def _merge_repair(
    read_api: GitHubApi,
    write_api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
    control_sha: str,
) -> dict[str, Any]:
    live = validate_generated_pr(
        read_api,
        pr,
        expected_bot_login=bot_login,
        expected_bot_id=bot_id,
    )
    require_automatic_trusted_gate(
        read_api,
        int(live["number"]),
        str(live["headSha"]),
        str(live["baseSha"]),
    )
    fresh = read_api.get(f"/pulls/{live['number']}")
    rebound = validate_generated_pr(
        read_api,
        fresh,
        expected_bot_login=bot_login,
        expected_bot_id=bot_id,
    )
    if rebound != live:
        raise ProtectedRemediationError("protected repair changed before guarded merge")
    gate_status = require_automatic_trusted_gate(
        read_api,
        int(live["number"]),
        str(live["headSha"]),
        str(live["baseSha"]),
    )
    require_current_control_revision(read_api, control_sha)
    if live["baseSha"] != control_sha:
        raise ProtectedRemediationError(
            "protected repair merge base is not the trusted control revision"
        )
    try:
        require_exact_owner_approval(
            read_api,
            lane=PROTECTED_SECURITY_LANE,
            number=int(live["number"]),
            head_sha=str(live["headSha"]),
            base_sha=str(live["baseSha"]),
            gate_status=gate_status,
            provenance=_protected_owner_review_provenance(
                live,
                bot_login=bot_login,
                bot_id=bot_id,
            ),
        )
    except (OwnerReviewPolicyBlock, OwnerReviewError) as exc:
        raise ProtectedRemediationError(str(exc)) from exc
    require_current_control_revision(read_api, control_sha)
    if live["baseSha"] != control_sha:
        raise ProtectedRemediationError(
            "protected repair merge base is not the trusted control revision"
        )
    result = write_api.put(
        f"/pulls/{live['number']}/merge",
        {"sha": live["headSha"], "merge_method": "merge"},
    )
    if not isinstance(result, dict) or result.get("merged") is not True:
        raise ProtectedRemediationError("GitHub declined guarded protected remediation merge")
    merge_sha = _require_sha(result.get("sha"), "protected repair merge SHA")
    if _current_main(read_api) != merge_sha:
        raise ProtectedRemediationError("main does not equal protected repair merge SHA")
    merge_commit = read_api.get(f"/git/commits/{merge_sha}")
    parents = (merge_commit or {}).get("parents") if isinstance(merge_commit, dict) else None
    head_commit = read_api.get(f"/git/commits/{live['headSha']}")
    if (
        not isinstance(parents, list)
        or [((parent or {}).get("sha")) for parent in parents] != [live["baseSha"], live["headSha"]]
        or ((merge_commit or {}).get("tree") or {}).get("sha")
        != ((head_commit or {}).get("tree") or {}).get("sha")
    ):
        raise ProtectedRemediationError("protected repair merge topology/tree drifted")
    return {
        "pr": live["number"],
        "mergeSha": merge_sha,
        "headSha": live["headSha"],
        "baseSha": live["baseSha"],
        "alertNumber": live["alertNumber"],
        "decision": "protected-repair-merged",
    }


def validate_control_revision() -> str:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    control_sha = _required_control_sha()
    require_current_control_revision(read_api, control_sha)
    return control_sha


def reconcile(*, allow_merge: bool) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    bot_login, bot_id = _require_author_identity(
        os.environ.get("PROTECTED_REMEDIATION_BOT_LOGIN", ""),
        int(os.environ.get("PROTECTED_REMEDIATION_BOT_ID", "0") or "0"),
    )
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    certificate_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    control_sha = _required_control_sha()
    require_current_control_revision(read_api, control_sha)
    write_api = GitHubApi(os.environ.get("PROTECTED_REMEDIATION_APP_TOKEN", ""), repository)
    config = load_config()

    active = _open_generated_repairs(read_api, bot_login=bot_login, bot_id=bot_id)
    if active:
        pr = read_api.get(
            f"/pulls/{_require_positive_int(active[0].get('number'), 'active repair PR number')}"
        )
        recovered = _recover_repair_publication(
            read_api,
            write_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )
        if recovered is None:
            print(
                json.dumps(
                    {
                        "decision": "stale-staged-protected-repair-closed",
                        "pr": pr.get("number"),
                    },
                    sort_keys=True,
                )
            )
            return 0
        pr = recovered
        if _generated_repair_is_stale(
            read_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
        ):
            print(
                json.dumps(
                    _close_stale_generated_repair(
                        read_api,
                        write_api,
                        pr,
                        bot_login=bot_login,
                        bot_id=bot_id,
                        control_sha=control_sha,
                    ),
                    sort_keys=True,
                )
            )
            return 0
        live = validate_generated_pr(
            read_api,
            pr,
            expected_bot_login=bot_login,
            expected_bot_id=bot_id,
            config=config,
        )
        try:
            require_automatic_trusted_gate(
                read_api,
                int(live["number"]),
                str(live["headSha"]),
                str(live["baseSha"]),
            )
        except TrustedStatusError:
            print(
                json.dumps(
                    {
                        "decision": "protected-repair-waiting",
                        "pr": live["number"],
                        "headSha": live["headSha"],
                        "reason": "Trusted PR Gate not yet admissible",
                    },
                    sort_keys=True,
                )
            )
            return 0
        if not allow_merge:
            print(json.dumps({"decision": "protected-repair-gate-ready", **live}, sort_keys=True))
            return 0
        print(
            json.dumps(
                _merge_repair(
                    read_api,
                    write_api,
                    pr,
                    bot_login=bot_login,
                    bot_id=bot_id,
                    control_sha=control_sha,
                ),
                sort_keys=True,
            )
        )
        return 0

    main_sha = require_current_control_revision(read_api, control_sha)
    if _reconcile_terminal_closure(
        read_api,
        certificate_api,
        bot_login=bot_login,
        bot_id=bot_id,
        current_main=main_sha,
    ):
        return 0
    candidates = _protected_route_candidates(
        read_api,
        main_sha=main_sha,
        config=config,
        bot_login=bot_login,
        bot_id=bot_id,
    )
    for record in candidates:
        try:
            validate_route_record(record, main_sha=main_sha)
        except ProtectedRemediationError:
            continue
        plan, _, repaired = _exact_repair_evidence(read_api, record, config=config)
        pr = _ensure_repair_pr(
            read_api,
            write_api,
            record,
            plan,
            repaired,
            bot_login=bot_login,
            bot_id=bot_id,
            control_sha=control_sha,
        )
        print(
            json.dumps(
                {
                    "decision": "protected-repair-created",
                    "pr": pr.get("number"),
                    "headSha": (pr.get("head") or {}).get("sha"),
                    "alert": record.get("alertNumber"),
                    "routeRecordDigest": record.get("recordDigest"),
                    "planDigest": plan.get("planDigest"),
                },
                sort_keys=True,
            )
        )
        return 0

    print(
        json.dumps(
            {"decision": "no-protected-repair-candidate", "mainSha": main_sha}, sort_keys=True
        )
    )
    return 0


def self_test() -> None:
    if not REPAIR_STRATEGIES:
        raise ProtectedRemediationError("protected authoring strategy set is empty")
    paths = [item.path for item in REPAIR_STRATEGIES]
    if len(paths) != len(set(paths)):
        raise ProtectedRemediationError("protected authoring strategy paths are duplicate")
    if any(path in SELF_AUTHORITY_PATHS for path in paths):
        raise ProtectedRemediationError("protected authoring policy includes self-authority")
    if MAX_CHANGED_FILES != 1:
        raise ProtectedRemediationError("protected authoring changed-file budget drifted")
    sample_branch = f"{BRANCH_PREFIX}1-{'a' * 64}-a1"
    sample_staging = f"{STAGING_BASE_PREFIX}1-{'a' * 64}-a1"
    if (
        BRANCH_RE.fullmatch(sample_branch) is None
        or STAGING_BASE_RE.fullmatch(sample_staging) is None
        or sample_branch == sample_staging
        or not sample_staging.startswith(STAGING_BASE_PREFIX)
    ):
        raise ProtectedRemediationError("protected publication namespace invariant drifted")
    for item in REPAIR_STRATEGIES:
        if not item.old or not item.new or item.old == item.new:
            raise ProtectedRemediationError(
                "protected authoring strategy transformation is invalid"
            )
        if not item.path.startswith(".github/"):
            raise ProtectedRemediationError(
                "initial protected authoring strategy escaped reviewed root"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent protected security remediation")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--validate-control-revision", action="store_true")
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    parser.add_argument("--approve-owner-review", action="store_true")
    parser.add_argument("--github-output")
    parser.add_argument("--merge-approved-pr", type=int)
    args = parser.parse_args()
    selected = (
        int(args.self_test)
        + int(args.validate_control_revision)
        + int(args.reconcile)
        + int(args.approve_owner_review)
        + int(args.merge_approved_pr is not None)
    )
    if selected != 1:
        raise ProtectedRemediationError("select exactly one protected remediation mode")
    if args.allow_merge and not args.reconcile:
        raise ProtectedRemediationError("--allow-merge requires --reconcile")
    if args.github_output and not args.approve_owner_review:
        raise ProtectedRemediationError("--github-output requires --approve-owner-review")
    if args.self_test:
        self_test()
        print(
            json.dumps(
                {
                    "result": "PASS",
                    "policyVersion": AUTHORING_POLICY_VERSION,
                    "strategies": len(REPAIR_STRATEGIES),
                },
                sort_keys=True,
            )
        )
        return
    if args.validate_control_revision:
        control_sha = validate_control_revision()
        print(json.dumps({"result": "PASS", "controlSha": control_sha}, sort_keys=True))
        return
    if args.approve_owner_review:
        publish_protected_owner_review(github_output=args.github_output)
        return
    if args.merge_approved_pr is not None:
        merge_approved_protected_repair(pr_number=args.merge_approved_pr)
        return
    reconcile(allow_merge=args.allow_merge)


if __name__ == "__main__":
    main()
