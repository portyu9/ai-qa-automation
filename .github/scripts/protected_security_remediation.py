#!/usr/bin/env python3
from __future__ import annotations

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
)

SCHEMA_VERSION = 1
AUTHORING_POLICY_VERSION = "protected-remediation-author-v1"
MAX_SOURCE_BYTES = 512 * 1024
MAX_PLAN_BYTES = 32 * 1024
MAX_CHANGED_FILES = 1
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


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
