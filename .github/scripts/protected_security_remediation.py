#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
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
)

SCHEMA_VERSION = 1
AUTHORING_POLICY_VERSION = "protected-remediation-author-v1"
MAX_SOURCE_BYTES = 512 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_CHANGED_FILES = 1
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
        ".github/scripts/protected_security_remediation.py",
        ".github/scripts/security_alert_routing.py",
        ".github/scripts/trusted_qualification.py",
        ".github/scripts/trusted_status.py",
        ".github/workflows/protected-security-remediation.yml",
        ".github/workflows/trusted-pr-auto.yml",
        "scripts/auto_trusted_bot_admission.py",
        "scripts/auto_trusted_preflight.py",
        "scripts/trusted_pr_control.py",
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
    if (
        not isinstance(login, str)
        or not login.endswith("[bot]")
        or login in DISALLOWED_AUTHOR_BOTS
    ):
        raise ProtectedRemediationError("protected author App login is not an independent bot identity")
    return login, _require_positive_int(user_id, "protected author App user id")


def branch_name(record: Mapping[str, Any]) -> str:
    validate_route_record(record, main_sha=_require_sha(record.get("baseSha"), "route base SHA"))
    alert = _require_positive_int(record.get("alertNumber"), "route alert number")
    fingerprint = _require_digest(record.get("fingerprint"), "route fingerprint")
    attempt = _require_positive_int(
        int(record["strategyAttemptCount"]) + 1, "protected repair attempt"
    )
    branch = f"{BRANCH_PREFIX}{alert}-{fingerprint}-a{attempt}"
    if BRANCH_RE.fullmatch(branch) is None:
        raise ProtectedRemediationError("protected repair branch is outside reviewed grammar")
    return branch


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
        raise ProtectedRemediationError(f"protected repair commit has invalid {label} trailer count")
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
    return MARKER_PREFIX + json.dumps(metadata, separators=(",", ":"), sort_keys=True) + MARKER_SUFFIX


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
    if metadata is None or set(metadata) != {"version", "base", "head", "routeRecord", "repairPlan"}:
        raise ProtectedRemediationError("protected repair marker is missing or malformed")
    if metadata.get("version") != 1 or metadata.get("base") != base_sha or metadata.get("head") != head_sha:
        raise ProtectedRemediationError("protected repair marker subject drifted")
    record = metadata.get("routeRecord")
    plan = metadata.get("repairPlan")
    if not isinstance(record, dict) or not isinstance(plan, dict):
        raise ProtectedRemediationError("protected repair marker evidence is malformed")
    strategy = validate_route_record(record, main_sha=base_sha)
    canonical_plan(plan)
    if plan.get("baseSha") != base_sha or plan.get("targetPath") != strategy.path:
        raise ProtectedRemediationError("protected repair plan subject drifted")
    if plan.get("changedFiles") != [strategy.path] or plan.get("maxChangedFiles") != MAX_CHANGED_FILES:
        raise ProtectedRemediationError("protected repair changed-file authority drifted")
    if head.get("ref") != branch_name(record):
        raise ProtectedRemediationError("protected repair branch does not match exact route subject")

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
        raise ProtectedRemediationError("live protected route drifted from persisted repair evidence")

    base_source = _contents_bytes(api, strategy.path, base_sha)
    repaired = revalidate_repair_plan(plan, base_source, record, main_sha=base_sha)
    if _contents_bytes(api, strategy.path, head_sha) != repaired:
        raise ProtectedRemediationError("protected repair head bytes do not equal deterministic output")

    files = api.list_all(f"/pulls/{number}/files", max_pages=2)
    if (
        len(files) != 1
        or not isinstance(files[0], dict)
        or files[0].get("filename") != strategy.path
        or files[0].get("status") != "modified"
    ):
        raise ProtectedRemediationError("protected repair diff escaped the exact one-file authority")

    commit = api.get(f"/commits/{head_sha}")
    if not isinstance(commit, dict) or commit.get("sha") != head_sha:
        raise ProtectedRemediationError("protected repair head commit is missing")
    author = commit.get("author") or {}
    parents = commit.get("parents")
    message = ((commit.get("commit") or {}).get("message"))
    if (
        author.get("login") != expected_bot_login
        or author.get("id") != expected_bot_id
        or author.get("type") != "Bot"
    ):
        raise ProtectedRemediationError("protected repair commit author is not the exact author App")
    if not isinstance(parents, list) or len(parents) != 1 or (parents[0] or {}).get("sha") != base_sha:
        raise ProtectedRemediationError("protected repair commit is not directly parented to exact main")
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


if __name__ == "__main__":
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
