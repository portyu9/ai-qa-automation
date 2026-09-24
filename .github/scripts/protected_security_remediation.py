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
from dataclasses import dataclass
from typing import Any, Mapping

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
from trusted_status import TrustedStatusError, require_automatic_trusted_gate

SCHEMA_VERSION = 1
AUTHORING_POLICY_VERSION = "protected-remediation-author-v1"
MAX_SOURCE_BYTES = 512 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_CHANGED_FILES = 1
MAX_API_BYTES = 8 * 1024 * 1024
MAX_OPEN_ALERTS = 100
MAX_PULL_HISTORY = 100
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
BRANCH_PREFIX = "automation/protected-security-remediation-"
BRANCH_RE = re.compile(
    r"^automation/protected-security-remediation-[1-9][0-9]*-[0-9a-f]{64}-a[1-9][0-9]*$"
)
MARKER_PREFIX = "<!-- aiqa-protected-security-remediation:"
MARKER_SUFFIX = " -->"
ROUTE_TRAILER_PREFIX = "Protected-Route-Record-Digest: "
PLAN_TRAILER_PREFIX = "Protected-Repair-Plan-Digest: "
DISALLOWED_AUTHOR_BOTS = frozenset(
    {"github-actions[bot]", "trusted-pr-gate[bot]", "dependabot[bot]"}
)


class ProtectedRemediationError(RuntimeError):
    """Protected remediation input is malformed or outside reviewed authority."""


@dataclass(frozen=True)
class RepairStrategy:
    rule: str
    path: str
    author_strategy: str
    old: bytes
    new: bytes


_SECURITY_AUTOHEAL_LOG_OLD = b"""                merge_evidence = _merge(api, number, validated_metadata, live, config)\n                print(\n                    json.dumps(\n                        {\n                            "pr": number,\n                            "decision": "repair-merged",\n                            "headSha": live["headSha"],\n                            **merge_evidence,\n                        },\n                        sort_keys=True,\n                    )\n                )\n"""

_SECURITY_AUTOHEAL_LOG_NEW = b"""                _merge(api, number, validated_metadata, live, config)\n                print(\n                    json.dumps(\n                        {\n                            "pr": number,\n                            "decision": "repair-merged",\n                            "headSha": live["headSha"],\n                        },\n                        sort_keys=True,\n                    )\n                )\n"""

REPAIR_STRATEGIES = (
    RepairStrategy(
        rule="py/clear-text-logging-sensitive-data",
        path=".github/scripts/security_autoheal.py",
        author_strategy="protected-security-autoheal-clear-text-log-v1",
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
        ".github/scripts/trusted_qualification.py",
        ".github/scripts/trusted_status.py",
        ".github/workflows/ci.yml",
        ".github/workflows/codeql.yml",
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
        _require_positive_int(
            int(record["strategyAttemptCount"]) + 1, "protected repair attempt"
        ),
    )


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
    try:
        raw = base64.b64decode(payload["content"], validate=True)
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
        attempts[number] = {
            PROTECTED_REMEDIATION_STRATEGY: _attempt_count(
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
        }
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
) -> str:
    branch = branch_name(record)
    encoded_ref = urllib.parse.quote(branch, safe="")
    status, existing = read_api.request_status("GET", f"/git/ref/heads/{encoded_ref}")
    if status == 200:
        if not isinstance(existing, dict):
            raise ProtectedRemediationError("existing protected repair ref is malformed")
        commit_sha = _require_sha(
            ((existing.get("object") or {}).get("sha")), "existing protected repair ref SHA"
        )
    elif status == 404:
        base_sha = _require_sha(record.get("baseSha"), "protected repair base SHA")
        base_commit = read_api.get(f"/git/commits/{base_sha}")
        base_tree = _require_sha(
            ((base_commit or {}).get("tree") or {}).get("sha"), "protected repair base tree SHA"
        )
        try:
            text = repaired.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtectedRemediationError("protected repair output is not UTF-8 text") from exc
        blob = write_api.post("/git/blobs", {"content": text, "encoding": "utf-8"})
        blob_sha = _require_sha((blob or {}).get("sha"), "protected repair blob SHA")
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
        commit = write_api.post(
            "/git/commits",
            {
                "message": repair_commit_message(record, plan),
                "tree": tree_sha,
                "parents": [base_sha],
            },
        )
        commit_sha = _require_sha((commit or {}).get("sha"), "protected repair commit SHA")
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
    else:
        raise ProtectedRemediationError(f"protected repair ref lookup failed with status {status}")

    commit = read_api.get(f"/commits/{commit_sha}")
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
    return commit_sha


def _find_pull_for_branch(api: GitHubApi, branch: str) -> dict[str, Any] | None:
    matches = _pulls_for_branch(api, branch)
    return matches[0] if matches else None


def _ensure_repair_pr(
    read_api: GitHubApi,
    write_api: GitHubApi,
    record: Mapping[str, Any],
    plan: Mapping[str, Any],
    repaired: bytes,
    *,
    bot_login: str,
    bot_id: int,
) -> dict[str, Any]:
    branch = branch_name(record)
    commit_sha = _create_repair_commit(
        read_api,
        write_api,
        record,
        plan,
        repaired,
        bot_login=bot_login,
        bot_id=bot_id,
    )
    existing = _find_pull_for_branch(read_api, branch)
    if existing is not None:
        if existing.get("state") != "open":
            raise ProtectedRemediationError(
                "protected repair branch is already bound to a closed PR"
            )
        pr = read_api.get(
            f"/pulls/{_require_positive_int(existing.get('number'), 'repair PR number')}"
        )
    else:
        body = (
            "Automated independent protected-control-plane remediation. "
            "The authoring App cannot publish Trusted PR Gate.\n\n"
            + marker(record, plan, head_sha=commit_sha)
        )
        created = write_api.post(
            "/pulls",
            {
                "title": f"security: remediate protected CodeQL alert #{record['alertNumber']}",
                "head": branch,
                "base": EXPECTED_BASE_BRANCH,
                "body": body,
                "draft": False,
            },
        )
        number = _require_positive_int((created or {}).get("number"), "created repair PR number")
        pr = read_api.get(f"/pulls/{number}")
    observed = validate_generated_pr(
        read_api,
        pr,
        expected_bot_login=bot_login,
        expected_bot_id=bot_id,
    )
    if observed["headSha"] != commit_sha:
        raise ProtectedRemediationError("protected repair PR head differs from exact repair commit")
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
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    if (
        (head.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or (base.get("repo") or {}).get("full_name") != EXPECTED_REPOSITORY
        or base.get("ref") != EXPECTED_BASE_BRANCH
    ):
        raise ProtectedRemediationError("stale repair cleanup repository/base identity drifted")
    _require_sha(head.get("sha"), "stale protected repair head SHA")
    base_sha = _require_sha(base.get("sha"), "stale protected repair base SHA")
    return _current_main(api) != base_sha


def _close_stale_generated_repair(
    write_api: GitHubApi,
    pr: Mapping[str, Any],
) -> dict[str, Any]:
    number = _require_positive_int(pr.get("number"), "stale protected repair PR number")
    result = write_api.patch(f"/pulls/{number}", {"state": "closed"})
    if (
        not isinstance(result, dict)
        or result.get("number") != number
        or result.get("state") != "closed"
    ):
        raise ProtectedRemediationError("GitHub did not acknowledge stale protected PR closure")
    return {
        "decision": "stale-protected-repair-closed",
        "pr": number,
        "headSha": _require_sha(
            ((pr.get("head") or {}).get("sha")), "stale protected repair head SHA"
        ),
        "baseSha": _require_sha(
            ((pr.get("base") or {}).get("sha")), "stale protected repair base SHA"
        ),
    }


def _merge_repair(
    read_api: GitHubApi,
    write_api: GitHubApi,
    pr: Mapping[str, Any],
    *,
    bot_login: str,
    bot_id: int,
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
    require_automatic_trusted_gate(
        read_api,
        int(live["number"]),
        str(live["headSha"]),
        str(live["baseSha"]),
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


def reconcile(*, allow_merge: bool) -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    bot_login, bot_id = _require_author_identity(
        os.environ.get("PROTECTED_REMEDIATION_BOT_LOGIN", ""),
        int(os.environ.get("PROTECTED_REMEDIATION_BOT_ID", "0") or "0"),
    )
    read_api = GitHubApi(os.environ.get("GITHUB_TOKEN", ""), repository)
    write_api = GitHubApi(os.environ.get("PROTECTED_REMEDIATION_APP_TOKEN", ""), repository)
    config = load_config()

    active = _open_generated_repairs(read_api, bot_login=bot_login, bot_id=bot_id)
    if active:
        pr = read_api.get(
            f"/pulls/{_require_positive_int(active[0].get('number'), 'active repair PR number')}"
        )
        if _generated_repair_is_stale(
            read_api,
            pr,
            bot_login=bot_login,
            bot_id=bot_id,
        ):
            print(json.dumps(_close_stale_generated_repair(write_api, pr), sort_keys=True))
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
                ),
                sort_keys=True,
            )
        )
        return 0

    main_sha = _current_main(read_api)
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
    parser.add_argument("--reconcile", action="store_true")
    parser.add_argument("--allow-merge", action="store_true")
    args = parser.parse_args()
    if args.self_test == args.reconcile:
        raise ProtectedRemediationError("select exactly one protected remediation mode")
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
    reconcile(allow_merge=args.allow_merge)


if __name__ == "__main__":
    main()
