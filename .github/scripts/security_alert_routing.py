#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = ROOT / ".github" / "security-autoheal.json"
ROUTING_POLICY_VERSION = "security-routing-v1"
EXPECTED_REPOSITORY = "portyu9/ai-qa-automation"
EXPECTED_BASE_BRANCH = "main"
MAX_ROUTE_RECORD_BYTES = 16 * 1024
MAX_ALERT_MESSAGE_BYTES = 64 * 1024
MAX_ALERT_BATCH = 100
MAX_ATTEMPT_STRATEGIES = 16
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
STRATEGY_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
AUTOFIX_EVIDENCE = {"available", "unavailable", "unknown"}
SAFE_RULES = frozenset(
    {
        "py/reflective-xss",
        "py/incomplete-url-substring-sanitization",
        "py/clear-text-logging-sensitive-data",
        "py/overly-permissive-file",
    }
)
MODEL_AUTOFIX_PATH_PREFIXES = ("src/", "examples/", "tests/")
DETERMINISTIC_ONLY_PATHS = frozenset(
    {
        "scripts/auto_trusted_report.py",
        "scripts/ci_contract_base.py",
        "scripts/verify_ci_contract.py",
        "scripts/verify_docs.py",
        "scripts/verify_fork_cloud_authority.py",
    }
)
NEVER_MODIFY_PATHS = frozenset(
    {
        ".github/",
        ".github/scripts/trusted_qualification.py",
        ".github/scripts/trusted_status.py",
        "scripts/auto_trusted_bot_admission.py",
        "scripts/auto_trusted_preflight.py",
        "scripts/trusted_pr_control.py",
    }
)
MODEL_AUTOFIX_STRATEGY = "github-codeql-autofix-v1"
PROTECTED_REMEDIATION_STRATEGY = "protected-independent-remediation-v1"
NO_REVIEWED_STRATEGY = "no-reviewed-strategy-v1"
CODE_OWNED_DETERMINISTIC_STRATEGIES = (
    (
        "py/overly-permissive-file",
        "deterministic-overly-permissive-test-file-v1",
        (),
        ("tests/",),
    ),
    (
        "py/clear-text-logging-sensitive-data",
        "deterministic-clear-text-log-v1",
        (
            "scripts/auto_trusted_report.py",
            "scripts/ci_contract_base.py",
            "scripts/verify_ci_contract.py",
            "scripts/verify_docs.py",
            "scripts/verify_fork_cloud_authority.py",
        ),
        (),
    ),
    (
        "py/reflective-xss",
        "deterministic-reference-sut-reflective-xss-v1",
        ("examples/reference_sut/app.py",),
        (),
    ),
)

SECURITY_SEVERITY_FLOORS = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
}

ROUTING_DECISIONS = {
    "ordinary-deterministic-autoheal",
    "ordinary-bounded-autofix",
    "protected-independent-remediation",
    "unsupported-rule",
    "unsupported-path",
    "below-severity-floor",
    "stale-alert",
    "attempt-budget-exhausted",
    "blocked-external-evidence",
}


class RoutingPolicyError(RuntimeError):
    """Malformed or ambiguous routing authority input; fail closed."""


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise RoutingPolicyError(f"{label} must be a canonical 40-character SHA")
    return value


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise RoutingPolicyError(f"{label} must be a positive integer")
    return value


def _safe_repository_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or value.startswith("/")
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise RoutingPolicyError("alert path is not a safe repository-relative path")
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise RoutingPolicyError("alert path contains an unsafe path segment")
    if not value.endswith(".py"):
        raise RoutingPolicyError("alert path must identify a Python source file")
    return value


def _path_matches(path: str, policy_path: str) -> bool:
    if policy_path.endswith("/"):
        return path.startswith(policy_path)
    return path == policy_path


def _security_severity(alert: Mapping[str, Any]) -> float:
    rule = alert.get("rule")
    if not isinstance(rule, Mapping):
        raise RoutingPolicyError("alert rule metadata is missing")
    value = rule.get("security_severity")
    if value is not None:
        if isinstance(value, bool):
            raise RoutingPolicyError("security severity is malformed")
        try:
            severity = float(value)
        except (TypeError, ValueError) as exc:
            raise RoutingPolicyError("security severity is malformed") from exc
        if not math.isfinite(severity) or severity < 0 or severity > 10:
            raise RoutingPolicyError("security severity is outside finite 0..10")
        return severity
    level = rule.get("security_severity_level")
    if isinstance(level, str) and level.lower() in SECURITY_SEVERITY_FLOORS:
        return SECURITY_SEVERITY_FLOORS[level.lower()]
    raise RoutingPolicyError("alert lacks a supported security severity")


def _alert_subject(alert: Mapping[str, Any], main_sha: str) -> dict[str, Any]:
    main_sha = _require_sha(main_sha, "current main SHA")
    number = _require_positive_int(alert.get("number"), "alert number")
    state = alert.get("state")
    if state not in {"open", "fixed", "dismissed"}:
        raise RoutingPolicyError("alert state is missing or unsupported")
    tool = alert.get("tool")
    if not isinstance(tool, Mapping) or tool.get("name") != "CodeQL":
        raise RoutingPolicyError("routing accepts only exact CodeQL tool metadata")
    rule = alert.get("rule")
    if not isinstance(rule, Mapping):
        raise RoutingPolicyError("alert rule metadata is missing")
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id or len(rule_id) > 256:
        raise RoutingPolicyError("alert rule id is missing or malformed")
    severity = _security_severity(alert)

    instance = alert.get("most_recent_instance")
    if not isinstance(instance, Mapping):
        raise RoutingPolicyError("alert most_recent_instance is missing")
    instance_state = instance.get("state")
    if instance_state not in {"open", "fixed", "dismissed"}:
        raise RoutingPolicyError("alert instance state is missing or unsupported")
    ref = instance.get("ref")
    if not isinstance(ref, str) or not ref:
        raise RoutingPolicyError("alert instance ref is missing")
    instance_sha = _require_sha(instance.get("commit_sha"), "alert instance SHA")
    location = instance.get("location")
    if not isinstance(location, Mapping):
        raise RoutingPolicyError("alert location is missing")
    path = _safe_repository_path(location.get("path"))
    line = _require_positive_int(location.get("start_line"), "alert start line")
    end_line = _require_positive_int(location.get("end_line"), "alert end line")
    start_column = _require_positive_int(location.get("start_column"), "alert start column")
    end_column = _require_positive_int(location.get("end_column"), "alert end column")
    if end_line < line or (end_line == line and end_column < start_column):
        raise RoutingPolicyError("alert location range is malformed")
    message = instance.get("message")
    if not isinstance(message, Mapping):
        raise RoutingPolicyError("alert message metadata is missing")
    text = message.get("text")
    if not isinstance(text, str):
        raise RoutingPolicyError("alert message text is missing")
    if len(text.encode("utf-8")) > MAX_ALERT_MESSAGE_BYTES:
        raise RoutingPolicyError("alert message exceeds the bounded routing limit")

    fingerprint_material = "\0".join(
        (
            str(number),
            rule_id,
            severity.hex(),
            state,
            instance_state,
            path,
            str(line),
            str(end_line),
            str(start_column),
            str(end_column),
            text,
            main_sha,
        )
    ).encode("utf-8")
    fingerprint = hashlib.sha256(fingerprint_material).hexdigest()
    return {
        "alertNumber": number,
        "state": state,
        "instanceState": instance_state,
        "tool": "CodeQL",
        "rule": rule_id,
        "securitySeverity": severity,
        "path": path,
        "line": line,
        "endLine": end_line,
        "startColumn": start_column,
        "endColumn": end_column,
        "baseSha": main_sha,
        "alertRef": ref,
        "alertInstanceSha": instance_sha,
        "fingerprint": fingerprint,
    }


def _routing_config(config: Mapping[str, Any]) -> dict[str, Any]:
    if config.get("repository") != EXPECTED_REPOSITORY:
        raise RoutingPolicyError("routing repository is not the code-owned repository")
    if config.get("baseBranch") != EXPECTED_BASE_BRANCH:
        raise RoutingPolicyError("routing base branch is not the code-owned branch")
    policy = config.get("routingPolicy")
    if not isinstance(policy, Mapping):
        raise RoutingPolicyError("routingPolicy is missing")
    expected_policy_keys = {
        "schemaVersion",
        "policyVersion",
        "protectedStrategy",
        "modelStrategy",
        "noReviewedStrategy",
        "deterministicStrategies",
    }
    if set(policy) != expected_policy_keys:
        raise RoutingPolicyError("routingPolicy keys must equal the code-owned schema")
    if policy.get("schemaVersion") != 1 or policy.get("policyVersion") != ROUTING_POLICY_VERSION:
        raise RoutingPolicyError("routingPolicy version is not code-owned")

    allowed_rules = config.get("allowedRules")
    if (
        not isinstance(allowed_rules, list)
        or not all(isinstance(value, str) for value in allowed_rules)
        or len(allowed_rules) != len(SAFE_RULES)
        or set(allowed_rules) != SAFE_RULES
    ):
        raise RoutingPolicyError("allowedRules must equal the code-owned rule set")
    minimum = config.get("minimumSecuritySeverity")
    if not isinstance(minimum, (int, float)) or isinstance(minimum, bool):
        raise RoutingPolicyError("minimumSecuritySeverity is malformed")
    minimum = float(minimum)
    if not math.isfinite(minimum) or minimum < 7.0 or minimum > 10:
        raise RoutingPolicyError("minimumSecuritySeverity must remain within reviewed 7..10")
    max_attempts = config.get("maxAttemptsPerAlert")
    if (
        isinstance(max_attempts, bool)
        or not isinstance(max_attempts, int)
        or not 1 <= max_attempts <= 3
    ):
        raise RoutingPolicyError("maxAttemptsPerAlert must remain within reviewed 1..3")

    model_prefixes = config.get("modelAutofixPathPrefixes")
    deterministic_only = config.get("deterministicOnlyPaths")
    never_modify = config.get("neverModifyPaths")
    if model_prefixes != list(MODEL_AUTOFIX_PATH_PREFIXES):
        raise RoutingPolicyError("modelAutofixPathPrefixes must equal the code-owned prefixes")
    if (
        not isinstance(deterministic_only, list)
        or not all(isinstance(value, str) for value in deterministic_only)
        or len(deterministic_only) != len(DETERMINISTIC_ONLY_PATHS)
        or set(deterministic_only) != DETERMINISTIC_ONLY_PATHS
    ):
        raise RoutingPolicyError("deterministicOnlyPaths must equal the code-owned paths")
    if (
        not isinstance(never_modify, list)
        or not all(isinstance(value, str) for value in never_modify)
        or len(never_modify) != len(NEVER_MODIFY_PATHS)
        or set(never_modify) != NEVER_MODIFY_PATHS
    ):
        raise RoutingPolicyError("neverModifyPaths must equal the code-owned protected roots")

    protected_strategy = policy.get("protectedStrategy")
    model_strategy = policy.get("modelStrategy")
    no_strategy = policy.get("noReviewedStrategy")
    if protected_strategy != PROTECTED_REMEDIATION_STRATEGY:
        raise RoutingPolicyError("protectedStrategy is not the code-owned strategy")
    if model_strategy != MODEL_AUTOFIX_STRATEGY:
        raise RoutingPolicyError("modelStrategy is not the code-owned strategy")
    if no_strategy != NO_REVIEWED_STRATEGY:
        raise RoutingPolicyError("noReviewedStrategy is not the code-owned strategy")

    raw_strategies = policy.get("deterministicStrategies")
    if not isinstance(raw_strategies, list) or not 1 <= len(raw_strategies) <= 16:
        raise RoutingPolicyError("deterministicStrategies is malformed")
    strategies: list[dict[str, Any]] = []
    seen_strategy_names: set[str] = set()
    for raw in raw_strategies:
        if not isinstance(raw, Mapping):
            raise RoutingPolicyError("deterministic strategy entry is malformed")
        if set(raw) != {"rule", "strategy", "paths", "pathPrefixes"}:
            raise RoutingPolicyError(
                "deterministic strategy keys are outside the code-owned schema"
            )
        rule = raw.get("rule")
        strategy = raw.get("strategy")
        paths = raw.get("paths")
        prefixes = raw.get("pathPrefixes")
        if (
            not isinstance(rule, str)
            or rule not in allowed_rules
            or not isinstance(strategy, str)
            or STRATEGY_RE.fullmatch(strategy) is None
            or strategy in seen_strategy_names
            or not isinstance(paths, list)
            or not isinstance(prefixes, list)
            or not all(isinstance(value, str) and value for value in paths + prefixes)
            or (not paths and not prefixes)
        ):
            raise RoutingPolicyError("deterministic strategy entry is invalid")
        seen_strategy_names.add(strategy)
        strategies.append(
            {
                "rule": rule,
                "strategy": strategy,
                "paths": tuple(paths),
                "pathPrefixes": tuple(prefixes),
            }
        )

    normalized_strategies = tuple(
        sorted(
            (
                entry["rule"],
                entry["strategy"],
                tuple(sorted(entry["paths"])),
                tuple(sorted(entry["pathPrefixes"])),
            )
            for entry in strategies
        )
    )
    expected_strategies = tuple(
        sorted(
            (
                rule,
                strategy,
                tuple(sorted(paths)),
                tuple(sorted(prefixes)),
            )
            for rule, strategy, paths, prefixes in CODE_OWNED_DETERMINISTIC_STRATEGIES
        )
    )
    if normalized_strategies != expected_strategies:
        raise RoutingPolicyError(
            "deterministicStrategies must equal the code-owned strategy matrix"
        )

    return {
        "allowedRules": frozenset(allowed_rules),
        "minimumSecuritySeverity": minimum,
        "maxAttemptsPerAlert": max_attempts,
        "modelAutofixPathPrefixes": tuple(model_prefixes),
        "deterministicOnlyPaths": tuple(deterministic_only),
        "neverModifyPaths": tuple(never_modify),
        "protectedControlPlanePaths": tuple(sorted(NEVER_MODIFY_PATHS | DETERMINISTIC_ONLY_PATHS)),
        "protectedStrategy": protected_strategy,
        "modelStrategy": model_strategy,
        "noReviewedStrategy": no_strategy,
        "deterministicStrategies": tuple(strategies),
    }


def _routing_policy_digest(policy: Mapping[str, Any]) -> str:
    deterministic = [
        {
            "rule": entry["rule"],
            "strategy": entry["strategy"],
            "paths": sorted(entry["paths"]),
            "pathPrefixes": sorted(entry["pathPrefixes"]),
        }
        for entry in policy["deterministicStrategies"]
    ]
    deterministic.sort(key=lambda entry: (entry["rule"], entry["strategy"]))
    material = {
        "repository": EXPECTED_REPOSITORY,
        "baseBranch": EXPECTED_BASE_BRANCH,
        "routingPolicyVersion": ROUTING_POLICY_VERSION,
        "allowedRules": sorted(policy["allowedRules"]),
        "minimumSecuritySeverity": policy["minimumSecuritySeverity"],
        "maxAttemptsPerAlert": policy["maxAttemptsPerAlert"],
        "modelAutofixPathPrefixes": list(policy["modelAutofixPathPrefixes"]),
        "deterministicOnlyPaths": sorted(policy["deterministicOnlyPaths"]),
        "neverModifyPaths": sorted(policy["neverModifyPaths"]),
        "protectedControlPlanePaths": sorted(policy["protectedControlPlanePaths"]),
        "protectedStrategy": policy["protectedStrategy"],
        "modelStrategy": policy["modelStrategy"],
        "noReviewedStrategy": policy["noReviewedStrategy"],
        "deterministicStrategies": deterministic,
    }
    return hashlib.sha256(
        json.dumps(material, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _deterministic_strategy(subject: Mapping[str, Any], policy: Mapping[str, Any]) -> str | None:
    matches: list[str] = []
    for entry in policy["deterministicStrategies"]:
        if entry["rule"] != subject["rule"]:
            continue
        if subject["path"] in entry["paths"] or any(
            subject["path"].startswith(prefix) for prefix in entry["pathPrefixes"]
        ):
            matches.append(entry["strategy"])
    if len(matches) > 1:
        raise RoutingPolicyError("alert matches multiple deterministic remediation strategies")
    return matches[0] if matches else None


def _attempt_count(attempts_by_strategy: Mapping[str, int] | None, strategy: str) -> int:
    attempts = attempts_by_strategy or {}
    if len(attempts) > MAX_ATTEMPT_STRATEGIES:
        raise RoutingPolicyError("attempt accounting exceeds the bounded strategy limit")
    for key, value in attempts.items():
        if not isinstance(key, str) or STRATEGY_RE.fullmatch(key) is None:
            raise RoutingPolicyError("attempt accounting contains an invalid strategy")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise RoutingPolicyError("attempt accounting contains an invalid count")
    return int(attempts.get(strategy, 0))


def _record(
    subject: Mapping[str, Any],
    *,
    decision: str,
    reason: str,
    authority: str,
    strategy: str,
    strategy_attempt_count: int,
    max_attempts: int,
    policy_digest: str,
    protected: bool,
    autofix_eligibility: str,
) -> dict[str, Any]:
    if decision not in ROUTING_DECISIONS:
        raise RoutingPolicyError("unreviewed routing decision")
    payload = {
        "schemaVersion": 1,
        "routingPolicyVersion": ROUTING_POLICY_VERSION,
        "routingPolicyDigest": policy_digest,
        "repository": EXPECTED_REPOSITORY,
        "baseBranch": EXPECTED_BASE_BRANCH,
        "decision": decision,
        "reason": reason,
        "authority": authority,
        "alertNumber": subject["alertNumber"],
        "alertState": subject["state"],
        "alertInstanceState": subject["instanceState"],
        "tool": subject["tool"],
        "rule": subject["rule"],
        "securitySeverity": subject["securitySeverity"],
        "path": subject["path"],
        "line": subject["line"],
        "endLine": subject["endLine"],
        "startColumn": subject["startColumn"],
        "endColumn": subject["endColumn"],
        "baseSha": subject["baseSha"],
        "alertRef": subject["alertRef"],
        "alertInstanceSha": subject["alertInstanceSha"],
        "fingerprint": subject["fingerprint"],
        "strategy": strategy,
        "strategyAttemptCount": strategy_attempt_count,
        "maxAttemptsPerStrategy": max_attempts,
        "protected": protected,
        "autofixEligibility": autofix_eligibility,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload["recordDigest"] = hashlib.sha256(canonical).hexdigest()
    canonical_with_digest = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(canonical_with_digest) > MAX_ROUTE_RECORD_BYTES:
        raise RoutingPolicyError("routing record exceeds the bounded persistence limit")
    return payload


def route_alert(
    alert: Mapping[str, Any],
    *,
    main_sha: str,
    config: Mapping[str, Any],
    attempts_by_strategy: Mapping[str, int] | None = None,
    autofix_eligibility: str = "unknown",
    expected_fingerprint: str | None = None,
    expected_strategy: str | None = None,
) -> dict[str, Any]:
    if autofix_eligibility not in AUTOFIX_EVIDENCE:
        raise RoutingPolicyError("autofix eligibility is outside the reviewed evidence states")
    subject = _alert_subject(alert, main_sha)
    policy = _routing_config(config)
    protected = any(
        _path_matches(subject["path"], path) for path in policy["protectedControlPlanePaths"]
    )

    deterministic = _deterministic_strategy(subject, policy)
    if protected:
        strategy = policy["protectedStrategy"]
    elif deterministic is not None:
        strategy = deterministic
    elif any(subject["path"].startswith(prefix) for prefix in policy["modelAutofixPathPrefixes"]):
        strategy = policy["modelStrategy"]
    else:
        strategy = policy["noReviewedStrategy"]

    attempts = _attempt_count(attempts_by_strategy, strategy)
    max_attempts = int(policy["maxAttemptsPerAlert"])
    policy_digest = _routing_policy_digest(policy)

    def make(decision: str, reason: str, authority: str = "none") -> dict[str, Any]:
        return _record(
            subject,
            decision=decision,
            reason=reason,
            authority=authority,
            strategy=strategy,
            strategy_attempt_count=attempts,
            max_attempts=max_attempts,
            policy_digest=policy_digest,
            protected=protected,
            autofix_eligibility=autofix_eligibility,
        )

    if subject["state"] != subject["instanceState"]:
        return make("stale-alert", "alert-and-instance-state-disagree")
    if subject["state"] != "open":
        return make("stale-alert", "alert-is-not-open")
    if (
        subject["alertRef"] != "refs/heads/main"
        or subject["alertInstanceSha"] != subject["baseSha"]
    ):
        return make("stale-alert", "alert-instance-is-not-exact-current-main")
    if expected_fingerprint is not None:
        if (
            not isinstance(expected_fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) is None
        ):
            raise RoutingPolicyError("expected fingerprint is malformed")
        if expected_fingerprint != subject["fingerprint"]:
            return make("stale-alert", "alert-fingerprint-drift")
    if expected_strategy is not None:
        if (
            not isinstance(expected_strategy, str)
            or STRATEGY_RE.fullmatch(expected_strategy) is None
        ):
            raise RoutingPolicyError("expected strategy is malformed")
        if expected_strategy != strategy:
            return make("stale-alert", "remediation-strategy-version-drift")
    if subject["rule"] not in policy["allowedRules"]:
        return make("unsupported-rule", "rule-is-outside-code-owned-allowlist")
    if subject["securitySeverity"] < policy["minimumSecuritySeverity"]:
        return make("below-severity-floor", "security-severity-is-below-policy-floor")
    if protected:
        if attempts >= max_attempts:
            return make("attempt-budget-exhausted", "protected-strategy-attempt-budget-exhausted")
        return make(
            "protected-independent-remediation",
            "protected-path-requires-independent-authority",
            "protected-independent-remediation",
        )
    if deterministic is not None:
        if attempts >= max_attempts:
            return make(
                "attempt-budget-exhausted", "deterministic-strategy-attempt-budget-exhausted"
            )
        return make(
            "ordinary-deterministic-autoheal",
            "exact-code-owned-deterministic-strategy",
            "security-autoheal-deterministic",
        )
    if any(_path_matches(subject["path"], path) for path in policy["deterministicOnlyPaths"]):
        return make("unsupported-path", "deterministic-only-path-has-no-matching-strategy")
    if strategy == policy["noReviewedStrategy"]:
        return make("unsupported-path", "path-is-outside-reviewed-remediation-surfaces")
    if attempts >= max_attempts:
        return make("attempt-budget-exhausted", "autofix-strategy-attempt-budget-exhausted")
    if autofix_eligibility != "available":
        return make(
            "blocked-external-evidence",
            "github-codeql-autofix-eligibility-is-not-available",
        )
    return make(
        "ordinary-bounded-autofix",
        "reviewed-model-path-with-live-autofix-evidence",
        "security-autoheal-autofix",
    )


def route_alerts(
    alerts: Sequence[Mapping[str, Any]],
    *,
    main_sha: str,
    config: Mapping[str, Any],
    attempts_by_alert: Mapping[int, Mapping[str, int]] | None = None,
    autofix_by_alert: Mapping[int, str] | None = None,
) -> list[dict[str, Any]]:
    if len(alerts) > MAX_ALERT_BATCH:
        raise RoutingPolicyError("alert batch exceeds the bounded routing limit")
    attempts_by_alert = attempts_by_alert or {}
    autofix_by_alert = autofix_by_alert or {}
    if len(attempts_by_alert) > MAX_ALERT_BATCH or len(autofix_by_alert) > MAX_ALERT_BATCH:
        raise RoutingPolicyError("per-alert routing evidence exceeds the bounded alert limit")
    for number in attempts_by_alert:
        _require_positive_int(number, "attempt evidence alert number")
    for number, state in autofix_by_alert.items():
        _require_positive_int(number, "autofix evidence alert number")
        if state not in AUTOFIX_EVIDENCE:
            raise RoutingPolicyError("per-alert autofix evidence contains an invalid state")
    seen: set[int] = set()
    records: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, Mapping):
            raise RoutingPolicyError("alert batch entries must be JSON objects")
        number = _require_positive_int(alert.get("number"), "alert number")
        if number in seen:
            raise RoutingPolicyError("alert batch contains duplicate alert identity")
        seen.add(number)
        records.append(
            route_alert(
                alert,
                main_sha=main_sha,
                config=config,
                attempts_by_strategy=attempts_by_alert.get(number),
                autofix_eligibility=autofix_by_alert.get(number, "unknown"),
            )
        )
    unknown_attempts = set(attempts_by_alert) - seen
    unknown_autofix = set(autofix_by_alert) - seen
    if unknown_attempts or unknown_autofix:
        raise RoutingPolicyError("per-alert routing evidence references an unobserved alert")
    return sorted(records, key=lambda row: int(row["alertNumber"]))


def canonical_record(record: Mapping[str, Any]) -> bytes:
    raw = dict(record)
    digest = raw.pop("recordDigest", None)
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RoutingPolicyError("routing record digest is missing or malformed")
    expected = hashlib.sha256(
        json.dumps(raw, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    if digest != expected:
        raise RoutingPolicyError("routing record digest does not match its content")
    raw["recordDigest"] = digest
    payload = (json.dumps(raw, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_ROUTE_RECORD_BYTES:
        raise RoutingPolicyError("routing record exceeds the bounded persistence limit")
    return payload


def _require_owned_nonwritable(info: os.stat_result, *, label: str) -> None:
    if info.st_uid != os.geteuid():
        raise RoutingPolicyError(f"{label} is not owned by the routing process")
    if info.st_mode & 0o022:
        raise RoutingPolicyError(f"{label} is writable by group or other users")


def _open_parent_directory(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise RoutingPolicyError("routing record persistence requires no-follow directory APIs")

    parts = path.parts
    if any(part == ".." for part in parts):
        raise RoutingPolicyError("routing record parent contains parent traversal")
    if path.is_absolute():
        current_fd = os.open("/", os.O_RDONLY | directory)
        components = parts[1:]
    else:
        current_fd = os.open(".", os.O_RDONLY | directory | nofollow)
        components = tuple(part for part in parts if part not in {"", "."})
    try:
        for component in components:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory | nofollow,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise RoutingPolicyError(
                    "routing record parent path contains an unavailable or symlink component"
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        info = os.fstat(current_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise RoutingPolicyError("routing record parent is not a directory")
        _require_owned_nonwritable(info, label="routing record parent")
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def _require_named_file_identity(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    *,
    label: str,
) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise RoutingPolicyError(f"{label} path identity changed during verification") from exc
    expected_identity = (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_uid,
        expected.st_gid,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    )
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if not stat.S_ISREG(current.st_mode) or current_identity != expected_identity:
        raise RoutingPolicyError(f"{label} path identity changed during verification")


def _require_parent_path_identity(path: Path, opened_fd: int, *, label: str) -> None:
    fresh_fd = _open_parent_directory(path)
    try:
        opened = os.fstat(opened_fd)
        fresh = os.fstat(fresh_fd)
        if (opened.st_dev, opened.st_ino) != (fresh.st_dev, fresh.st_ino):
            raise RoutingPolicyError(f"{label} parent path identity changed during verification")
    finally:
        os.close(fresh_fd)


def _read_record_at(parent_fd: int, name: str) -> bytes | None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RoutingPolicyError(
            "routing record verification requires no-follow non-blocking file APIs"
        )
    try:
        fd = os.open(name, os.O_RDONLY | nofollow | nonblock, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RoutingPolicyError("existing routing record path is not a regular file") from exc
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_ROUTE_RECORD_BYTES:
            raise RoutingPolicyError("existing routing record path is not a bounded regular file")
        _require_owned_nonwritable(initial, label="existing routing record")
        payload = bytearray()
        while len(payload) <= MAX_ROUTE_RECORD_BYTES:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_ROUTE_RECORD_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_ROUTE_RECORD_BYTES:
            raise RoutingPolicyError("existing routing record exceeds the persistence limit")
        final = os.fstat(fd)
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
            final.st_mtime_ns,
            final.st_ctime_ns,
        ):
            raise RoutingPolicyError("existing routing record changed during verification")
        _require_named_file_identity(
            parent_fd,
            name,
            final,
            label="existing routing record",
        )
        return bytes(payload)
    finally:
        os.close(fd)


def _reconcile_identical_record(
    parent_fd: int,
    name: str,
    payload: bytes,
    *,
    parent_path: Path,
) -> None:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RoutingPolicyError(
            "routing record reconciliation requires no-follow non-blocking file APIs"
        )
    try:
        fd = os.open(name, os.O_RDONLY | nofollow | nonblock, dir_fd=parent_fd)
    except OSError as exc:
        raise RoutingPolicyError(
            "routing record changed during durability reconciliation"
        ) from exc
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_ROUTE_RECORD_BYTES:
            raise RoutingPolicyError(
                "routing record changed during durability reconciliation"
            )
        _require_owned_nonwritable(initial, label="existing routing record")
        observed = bytearray()
        while len(observed) <= MAX_ROUTE_RECORD_BYTES:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_ROUTE_RECORD_BYTES + 1 - len(observed)),
            )
            if not chunk:
                break
            observed.extend(chunk)
        if bytes(observed) != payload:
            raise RoutingPolicyError(
                "routing record changed during durability reconciliation"
            )
        before_sync = os.fstat(fd)
        if (
            initial.st_dev,
            initial.st_ino,
            initial.st_mode,
            initial.st_uid,
            initial.st_gid,
            initial.st_size,
            initial.st_mtime_ns,
            initial.st_ctime_ns,
        ) != (
            before_sync.st_dev,
            before_sync.st_ino,
            before_sync.st_mode,
            before_sync.st_uid,
            before_sync.st_gid,
            before_sync.st_size,
            before_sync.st_mtime_ns,
            before_sync.st_ctime_ns,
        ):
            raise RoutingPolicyError(
                "routing record changed during durability reconciliation"
            )
        _require_named_file_identity(
            parent_fd,
            name,
            before_sync,
            label="existing routing record",
        )
        os.fsync(fd)
        after_file_sync = os.fstat(fd)
        if (
            before_sync.st_dev,
            before_sync.st_ino,
            before_sync.st_mode,
            before_sync.st_uid,
            before_sync.st_gid,
            before_sync.st_size,
            before_sync.st_mtime_ns,
            before_sync.st_ctime_ns,
        ) != (
            after_file_sync.st_dev,
            after_file_sync.st_ino,
            after_file_sync.st_mode,
            after_file_sync.st_uid,
            after_file_sync.st_gid,
            after_file_sync.st_size,
            after_file_sync.st_mtime_ns,
            after_file_sync.st_ctime_ns,
        ):
            raise RoutingPolicyError(
                "routing record changed during durability reconciliation"
            )
        _require_named_file_identity(
            parent_fd,
            name,
            after_file_sync,
            label="existing routing record",
        )
        os.fsync(parent_fd)
        after_parent_sync = os.fstat(fd)
        if (
            after_file_sync.st_dev,
            after_file_sync.st_ino,
            after_file_sync.st_mode,
            after_file_sync.st_uid,
            after_file_sync.st_gid,
            after_file_sync.st_size,
            after_file_sync.st_mtime_ns,
            after_file_sync.st_ctime_ns,
        ) != (
            after_parent_sync.st_dev,
            after_parent_sync.st_ino,
            after_parent_sync.st_mode,
            after_parent_sync.st_uid,
            after_parent_sync.st_gid,
            after_parent_sync.st_size,
            after_parent_sync.st_mtime_ns,
            after_parent_sync.st_ctime_ns,
        ):
            raise RoutingPolicyError(
                "routing record changed during durability reconciliation"
            )
        _require_named_file_identity(
            parent_fd,
            name,
            after_parent_sync,
            label="existing routing record",
        )
    finally:
        os.close(fd)
    _require_parent_path_identity(
        parent_path,
        parent_fd,
        label="routing record",
    )


def persist_record(path: Path, record: Mapping[str, Any]) -> bool:
    payload = canonical_record(record)
    name = path.name
    if not name or name in {".", ".."}:
        raise RoutingPolicyError("routing record target name is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RoutingPolicyError(
            "routing record persistence requires no-follow non-blocking file APIs"
        )
    parent_fd = _open_parent_directory(path.parent)
    temp_name: str | None = None
    try:
        existing = _read_record_at(parent_fd, name)
        if existing is not None:
            if existing == payload:
                _reconcile_identical_record(
                    parent_fd,
                    name,
                    payload,
                    parent_path=path.parent,
                )
                return False
            raise RoutingPolicyError("routing record path already contains different evidence")

        for _ in range(8):
            candidate = f".{name}.{secrets.token_hex(8)}.tmp"
            try:
                temp_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise RoutingPolicyError("routing record temporary publication failed") from exc
            temp_name = candidate
            break
        else:
            raise RoutingPolicyError("unable to allocate bounded routing record temporary file")

        try:
            view = memoryview(payload)
            while view:
                written = os.write(temp_fd, view)
                if written <= 0:
                    raise RoutingPolicyError("routing record write made no forward progress")
                view = view[written:]
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)

        try:
            os.link(
                temp_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            existing = _read_record_at(parent_fd, name)
            if existing != payload:
                raise RoutingPolicyError(
                    "concurrent routing record publication conflicted"
                ) from exc
            _reconcile_identical_record(
                parent_fd,
                name,
                payload,
                parent_path=path.parent,
            )
            return False
        except OSError as exc:
            raise RoutingPolicyError("routing record atomic publication failed") from exc

        os.fsync(parent_fd)
        published = _read_record_at(parent_fd, name)
        if published != payload:
            raise RoutingPolicyError("routing record publication read-back mismatch")
        _require_parent_path_identity(
            path.parent,
            parent_fd,
            label="routing record",
        )
        return True
    finally:
        if temp_name is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=parent_fd)
        os.close(parent_fd)


def _strict_json_loads(payload: bytes, *, label: str) -> Any:
    def reject_constant(value: str) -> Any:
        raise RoutingPolicyError(f"{label} contains non-finite JSON constant: {value}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RoutingPolicyError(f"{label} contains duplicate object key: {key}")
            result[key] = value
        return result

    try:
        text = payload.decode("utf-8")
        return json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RoutingPolicyError(f"{label} is not strict canonical JSON") from exc


def _read_json(path: Path, *, max_bytes: int, label: str) -> Any:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if not nofollow or not nonblock:
        raise RoutingPolicyError(f"{label} requires no-follow non-blocking file ingestion")
    name = path.name
    if not name or name in {".", ".."}:
        raise RoutingPolicyError(f"{label} path has an invalid target name")
    flags = os.O_RDONLY | nofollow | nonblock | getattr(os, "O_BINARY", 0)
    parent_fd = _open_parent_directory(path.parent)
    try:
        try:
            fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as exc:
            raise RoutingPolicyError(
                f"{label} cannot be opened as a regular non-symlink file"
            ) from exc
        try:
            initial = os.fstat(fd)
            if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
                raise RoutingPolicyError(f"{label} must be a bounded regular file")
            _require_owned_nonwritable(initial, label=label)
            payload = bytearray()
            while len(payload) <= max_bytes:
                chunk = os.read(fd, min(1024 * 1024, max_bytes + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > max_bytes:
                raise RoutingPolicyError(f"{label} exceeds the bounded ingestion limit")
            final = os.fstat(fd)
            if (
                initial.st_dev,
                initial.st_ino,
                initial.st_size,
                initial.st_mtime_ns,
                initial.st_ctime_ns,
            ) != (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            ):
                raise RoutingPolicyError(f"{label} changed during ingestion")
            _require_named_file_identity(
                parent_fd,
                name,
                final,
                label=label,
            )
        finally:
            os.close(fd)
        _require_parent_path_identity(
            path.parent,
            parent_fd,
            label=label,
        )
    finally:
        os.close(parent_fd)
    return _strict_json_loads(bytes(payload), label=label)


def load_config(path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    payload = _read_json(path, max_bytes=256 * 1024, label="routing config")
    if not isinstance(payload, dict):
        raise RoutingPolicyError("routing config must be a JSON object")
    _routing_config(payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--alert", type=Path, required=True)
    parser.add_argument("--main-sha", required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument(
        "--autofix-eligibility",
        choices=sorted(AUTOFIX_EVIDENCE),
        default="unknown",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    alert = _read_json(args.alert, max_bytes=512 * 1024, label="alert input")
    if not isinstance(alert, dict):
        raise RoutingPolicyError("alert input must be a JSON object")
    record = route_alert(
        alert,
        main_sha=args.main_sha,
        config=load_config(args.config),
        autofix_eligibility=args.autofix_eligibility,
    )
    persist_record(args.output, record)
    print(
        json.dumps(
            {
                "decision": record["decision"],
                "recordDigest": record["recordDigest"],
                "routingPolicyVersion": record["routingPolicyVersion"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
