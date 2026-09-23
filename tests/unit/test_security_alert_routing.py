from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
ROUTING_SCRIPT = ROOT / ".github" / "scripts" / "security_alert_routing.py"
AUTOHEAL_SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = ROUTING_SCRIPT.parent
CONFIG_PATH = ROOT / ".github" / "security-autoheal.json"

MAIN = "a" * 40


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


routing = _load(ROUTING_SCRIPT, "security_alert_routing_test")
autoheal = _load(AUTOHEAL_SCRIPT, "security_autoheal_routing_drift_test")


def _config() -> dict[str, Any]:
    return routing.load_config(CONFIG_PATH)


def _alert(
    *,
    number: int = 7,
    rule: str = "py/reflective-xss",
    path: str = "examples/reference_sut/app.py",
    sha: str = MAIN,
    ref: str = "refs/heads/main",
    severity: str = "8.8",
    state: str = "open",
    message: str = "test finding",
) -> dict[str, Any]:
    return {
        "number": number,
        "state": state,
        "tool": {"name": "CodeQL"},
        "rule": {"id": rule, "security_severity": severity},
        "most_recent_instance": {
            "ref": ref,
            "commit_sha": sha,
            "location": {"path": path, "start_line": 12},
            "message": {"text": message},
        },
    }


@pytest.mark.parametrize(
    ("rule", "path", "autofix", "decision", "strategy"),
    (
        (
            "py/reflective-xss",
            "examples/reference_sut/app.py",
            "unknown",
            "ordinary-deterministic-autoheal",
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
        ),
        (
            "py/incomplete-url-substring-sanitization",
            "src/ai_qa_automation/example.py",
            "available",
            "ordinary-bounded-autofix",
            autoheal.MODEL_AUTOFIX_STRATEGY,
        ),
        (
            "py/clear-text-logging-sensitive-data",
            "scripts/verify_docs.py",
            "unknown",
            "ordinary-deterministic-autoheal",
            autoheal.CLEAR_TEXT_LOG_STRATEGY,
        ),
        (
            "py/overly-permissive-file",
            "tests/unit/test_permissions.py",
            "unknown",
            "ordinary-deterministic-autoheal",
            autoheal.OVERLY_PERMISSIVE_TEST_STRATEGY,
        ),
    ),
)
def test_every_current_allowed_rule_has_explicit_tested_route(
    rule: str,
    path: str,
    autofix: str,
    decision: str,
    strategy: str,
) -> None:
    record = routing.route_alert(
        _alert(rule=rule, path=path),
        main_sha=MAIN,
        config=_config(),
        autofix_eligibility=autofix,
    )

    assert record["decision"] == decision
    assert record["strategy"] == strategy
    assert record["baseSha"] == MAIN
    assert record["alertInstanceSha"] == MAIN
    assert record["routingPolicyVersion"] == routing.ROUTING_POLICY_VERSION
    assert record["alertState"] == "open"
    assert routing.re.fullmatch(r"[0-9a-f]{64}", record["routingPolicyDigest"]) is not None


def test_alert_7_routes_to_ordinary_deterministic_autoheal() -> None:
    record = routing.route_alert(
        _alert(number=7),
        main_sha=MAIN,
        config=_config(),
    )

    assert record["decision"] == "ordinary-deterministic-autoheal"
    assert record["authority"] == "security-autoheal-deterministic"
    assert record["protected"] is False


def test_alert_17_class_routes_to_independent_protected_authority() -> None:
    record = routing.route_alert(
        _alert(
            number=17,
            rule="py/clear-text-logging-sensitive-data",
            path=".github/scripts/security_autoheal.py",
        ),
        main_sha=MAIN,
        config=_config(),
    )

    assert record["decision"] == "protected-independent-remediation"
    assert record["authority"] == "protected-independent-remediation"
    assert record["strategy"] == "protected-independent-remediation-v1"
    assert record["protected"] is True


@pytest.mark.parametrize(
    "path",
    (
        "../outside.py",
        "src/../.github/workflows/escape.py",
        "/absolute.py",
        "src\\windows.py",
        "src//double.py",
    ),
)
def test_path_traversal_and_noncanonical_paths_fail_closed(path: str) -> None:
    with pytest.raises(routing.RoutingPolicyError, match="path"):
        routing.route_alert(
            _alert(path=path),
            main_sha=MAIN,
            config=_config(),
        )


@pytest.mark.parametrize(
    "tool",
    (
        {},
        {"name": "codeql"},
        {"name": "GitHub Advanced Security"},
        {"name": "CodeQL", "actor": {"login": "github-actions[bot]"}},
    ),
)
def test_missing_or_ambiguous_scanner_identity_fails_closed(tool: dict[str, Any]) -> None:
    alert = _alert()
    alert["tool"] = tool

    if tool.get("name") == "CodeQL":
        record = routing.route_alert(alert, main_sha=MAIN, config=_config())
        assert record["decision"] == "ordinary-deterministic-autoheal"
    else:
        with pytest.raises(routing.RoutingPolicyError, match="CodeQL"):
            routing.route_alert(alert, main_sha=MAIN, config=_config())


def test_alert_supplied_actor_spoofing_cannot_choose_authority() -> None:
    baseline = _alert()
    spoofed = deepcopy(baseline)
    spoofed["actor"] = {
        "login": "github-advanced-security[bot]",
        "id": autoheal.GITHUB_ACTIONS_USER_ID,
    }
    spoofed["authority"] = "protected-independent-remediation"

    baseline_record = routing.route_alert(baseline, main_sha=MAIN, config=_config())
    spoofed_record = routing.route_alert(spoofed, main_sha=MAIN, config=_config())

    assert spoofed_record == baseline_record
    assert spoofed_record["authority"] == "security-autoheal-deterministic"


@pytest.mark.parametrize(
    ("mutator", "reason"),
    (
        (lambda alert: alert.update(state="fixed"), "alert-is-not-open"),
        (
            lambda alert: alert["most_recent_instance"].update(commit_sha="b" * 40),
            "alert-instance-is-not-exact-current-main",
        ),
        (
            lambda alert: alert["most_recent_instance"].update(ref="refs/heads/feature"),
            "alert-instance-is-not-exact-current-main",
        ),
    ),
)
def test_stale_alert_instances_have_explicit_terminal_route(
    mutator: Any,
    reason: str,
) -> None:
    alert = _alert()
    mutator(alert)

    record = routing.route_alert(alert, main_sha=MAIN, config=_config())

    assert record["decision"] == "stale-alert"
    assert record["reason"] == reason
    assert record["alertState"] == alert["state"]


def test_fingerprint_and_strategy_drift_fail_closed_as_stale() -> None:
    baseline = routing.route_alert(_alert(), main_sha=MAIN, config=_config())

    moved = _alert(path="examples/reference_sut/renamed.py")
    moved_record = routing.route_alert(
        moved,
        main_sha=MAIN,
        config=_config(),
        expected_fingerprint=baseline["fingerprint"],
    )
    assert moved_record["decision"] == "stale-alert"
    assert moved_record["reason"] == "alert-fingerprint-drift"

    strategy_record = routing.route_alert(
        _alert(),
        main_sha=MAIN,
        config=_config(),
        expected_strategy=autoheal.MODEL_AUTOFIX_STRATEGY,
    )
    assert strategy_record["decision"] == "stale-alert"
    assert strategy_record["reason"] == "remediation-strategy-version-drift"


def test_routing_record_binds_exact_normalized_policy_inputs() -> None:
    baseline_config = _config()
    baseline = routing.route_alert(
        _alert(severity="8.8"),
        main_sha=MAIN,
        config=baseline_config,
    )

    tightened_config = _config()
    tightened_config["minimumSecuritySeverity"] = 8.0
    tightened = routing.route_alert(
        _alert(severity="8.8"),
        main_sha=MAIN,
        config=tightened_config,
    )

    assert baseline["decision"] == tightened["decision"]
    assert baseline["routingPolicyVersion"] == tightened["routingPolicyVersion"]
    assert baseline["routingPolicyDigest"] != tightened["routingPolicyDigest"]
    assert baseline["recordDigest"] != tightened["recordDigest"]


def test_changed_rule_and_severity_change_the_routing_truth() -> None:
    unsupported = routing.route_alert(
        _alert(rule="py/unreviewed-rule"),
        main_sha=MAIN,
        config=_config(),
    )
    assert unsupported["decision"] == "unsupported-rule"

    low = routing.route_alert(
        _alert(severity="6.9"),
        main_sha=MAIN,
        config=_config(),
    )
    assert low["decision"] == "below-severity-floor"


def test_protected_path_cannot_fall_through_to_model_autofix() -> None:
    record = routing.route_alert(
        _alert(
            rule="py/incomplete-url-substring-sanitization",
            path=".github/scripts/ordinary_name.py",
        ),
        main_sha=MAIN,
        config=_config(),
        autofix_eligibility="available",
    )

    assert record["decision"] == "protected-independent-remediation"
    assert record["authority"] == "protected-independent-remediation"


def test_attempt_budget_is_strategy_version_scoped() -> None:
    current = autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    exhausted = routing.route_alert(
        _alert(),
        main_sha=MAIN,
        config=_config(),
        attempts_by_strategy={current: 2},
    )
    assert exhausted["decision"] == "attempt-budget-exhausted"

    reviewed_new_epoch = routing.route_alert(
        _alert(),
        main_sha=MAIN,
        config=_config(),
        attempts_by_strategy={"deterministic-reference-sut-reflective-xss-v0": 2},
    )
    assert reviewed_new_epoch["decision"] == "ordinary-deterministic-autoheal"
    assert reviewed_new_epoch["strategyAttemptCount"] == 0


@pytest.mark.parametrize("evidence", ("unknown", "unavailable"))
def test_model_route_requires_live_autofix_evidence(evidence: str) -> None:
    record = routing.route_alert(
        _alert(
            rule="py/incomplete-url-substring-sanitization",
            path="src/ai_qa_automation/example.py",
        ),
        main_sha=MAIN,
        config=_config(),
        autofix_eligibility=evidence,
    )

    assert record["decision"] == "blocked-external-evidence"


def test_unreviewed_path_has_explicit_nonmutation_route() -> None:
    record = routing.route_alert(
        _alert(
            rule="py/incomplete-url-substring-sanitization",
            path="docs/generated_example.py",
        ),
        main_sha=MAIN,
        config=_config(),
        autofix_eligibility="available",
    )

    assert record["decision"] == "unsupported-path"
    assert record["authority"] == "none"


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (
            lambda config: config.update(
                allowedRules=[*config["allowedRules"], "py/unreviewed-rule"]
            ),
            "code-owned rule set",
        ),
        (
            lambda config: config.update(
                modelAutofixPathPrefixes=["src/", "examples/", "tests/", ".github/"]
            ),
            "code-owned prefixes",
        ),
        (
            lambda config: config.update(
                neverModifyPaths=[path for path in config["neverModifyPaths"] if path != ".github/"]
            ),
            "code-owned protected roots",
        ),
        (
            lambda config: config["routingPolicy"].update(modelStrategy="github-codeql-autofix-v2"),
            "code-owned strategy",
        ),
        (
            lambda config: config["routingPolicy"]["deterministicStrategies"][0].update(
                pathPrefixes=["tests/", "src/"]
            ),
            "code-owned strategy matrix",
        ),
        (
            lambda config: config["routingPolicy"]["deterministicStrategies"][1]["paths"].append(
                "scripts/unreviewed_logger.py"
            ),
            "code-owned strategy matrix",
        ),
        (
            lambda config: config["routingPolicy"]["deterministicStrategies"][2].update(
                strategy="deterministic-reference-sut-reflective-xss-v2"
            ),
            "code-owned strategy matrix",
        ),
        (
            lambda config: config["routingPolicy"]["deterministicStrategies"].append(
                {
                    "rule": "py/reflective-xss",
                    "strategy": "deterministic-extra-reflective-xss-v1",
                    "paths": ["src/ai_qa_automation/extra.py"],
                    "pathPrefixes": [],
                }
            ),
            "code-owned strategy matrix",
        ),
    ),
)
def test_routing_authority_surfaces_cannot_expand_by_config_only(
    mutate: Any,
    message: str,
) -> None:
    config = _config()
    mutate(config)

    with pytest.raises(routing.RoutingPolicyError, match=message):
        routing.route_alert(_alert(), main_sha=MAIN, config=config)


def test_batch_rejects_evidence_for_unobserved_alerts() -> None:
    with pytest.raises(routing.RoutingPolicyError, match="unobserved alert"):
        routing.route_alerts(
            [_alert(number=7)],
            main_sha=MAIN,
            config=_config(),
            attempts_by_alert={17: {}},
        )

    with pytest.raises(routing.RoutingPolicyError, match="unobserved alert"):
        routing.route_alerts(
            [_alert(number=7)],
            main_sha=MAIN,
            config=_config(),
            autofix_by_alert={17: "available"},
        )


def test_strict_json_ingestion_rejects_duplicate_keys_and_nonfinite_constants(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"number":7,"number":8}', encoding="utf-8")
    with pytest.raises(routing.RoutingPolicyError, match="duplicate object key"):
        routing._read_json(duplicate, max_bytes=1024, label="alert input")

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"severity":NaN}', encoding="utf-8")
    with pytest.raises(routing.RoutingPolicyError, match="non-finite JSON constant"):
        routing._read_json(nonfinite, max_bytes=1024, label="alert input")


@pytest.mark.parametrize("severity", ("nan", "inf", "-inf"))
def test_nonfinite_security_severity_fails_closed(severity: str) -> None:
    with pytest.raises(routing.RoutingPolicyError, match=r"finite 0\.\.10"):
        routing.route_alert(
            _alert(severity=severity),
            main_sha=MAIN,
            config=_config(),
        )


def test_malformed_authority_collections_fail_as_policy_errors() -> None:
    config = _config()
    config["allowedRules"] = [{"id": "py/reflective-xss"}]

    with pytest.raises(routing.RoutingPolicyError):
        routing.route_alert(_alert(), main_sha=MAIN, config=config)


def test_json_ingestion_rejects_symlink_input(tmp_path: Path) -> None:
    actual = tmp_path / "alert.json"
    actual.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(actual)

    with pytest.raises(routing.RoutingPolicyError, match="cannot be opened"):
        routing._read_json(link, max_bytes=1024, label="alert input")


def test_routing_policy_is_bound_to_current_autoheal_strategy_constants() -> None:
    config = _config()
    policy = config["routingPolicy"]

    assert set(config["allowedRules"]) == autoheal.SAFE_RULES
    assert policy["modelStrategy"] == autoheal.MODEL_AUTOFIX_STRATEGY
    assert {entry["strategy"] for entry in policy["deterministicStrategies"]} == {
        autoheal.OVERLY_PERMISSIVE_TEST_STRATEGY,
        autoheal.CLEAR_TEXT_LOG_STRATEGY,
        autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    clear_text = next(
        entry
        for entry in policy["deterministicStrategies"]
        if entry["strategy"] == autoheal.CLEAR_TEXT_LOG_STRATEGY
    )
    assert set(clear_text["paths"]) == set(autoheal.DETERMINISTIC_LOG_REPAIRS)


def test_concurrent_alert_batch_is_bounded_unique_and_deterministically_ordered() -> None:
    alerts = [
        _alert(number=17, path=".github/scripts/security_autoheal.py"),
        _alert(number=7),
    ]

    records = routing.route_alerts(
        alerts,
        main_sha=MAIN,
        config=_config(),
    )

    assert [record["alertNumber"] for record in records] == [7, 17]
    assert records[0]["decision"] == "ordinary-deterministic-autoheal"
    assert records[1]["decision"] == "protected-independent-remediation"

    with pytest.raises(routing.RoutingPolicyError, match="duplicate"):
        routing.route_alerts(
            [_alert(number=7), _alert(number=7)],
            main_sha=MAIN,
            config=_config(),
        )

    with pytest.raises(routing.RoutingPolicyError, match="batch"):
        routing.route_alerts(
            [_alert(number=index + 1) for index in range(routing.MAX_ALERT_BATCH + 1)],
            main_sha=MAIN,
            config=_config(),
        )


def test_attempt_accounting_has_resource_bounds() -> None:
    attempts = {f"strategy-{index}-v1": 0 for index in range(routing.MAX_ATTEMPT_STRATEGIES + 1)}
    with pytest.raises(routing.RoutingPolicyError, match="bounded strategy"):
        routing.route_alert(
            _alert(),
            main_sha=MAIN,
            config=_config(),
            attempts_by_strategy=attempts,
        )


def test_routing_record_persistence_is_atomic_idempotent_and_conflict_safe(
    tmp_path: Path,
) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    target = tmp_path / "route.json"

    assert routing.persist_record(target, record) is True
    first = target.read_bytes()
    assert routing.persist_record(target, record) is False
    assert target.read_bytes() == first

    tampered = dict(record)
    tampered["reason"] = "tampered"
    raw = dict(tampered)
    raw.pop("recordDigest")
    tampered["recordDigest"] = routing.hashlib.sha256(
        routing.json.dumps(raw, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    with pytest.raises(routing.RoutingPolicyError, match="different evidence"):
        routing.persist_record(target, tampered)


def test_routing_record_rejects_digest_tampering(tmp_path: Path) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    record["reason"] = "tampered-without-redigest"

    with pytest.raises(routing.RoutingPolicyError, match="digest does not match"):
        routing.persist_record(tmp_path / "route.json", record)


def test_routing_record_persistence_rejects_symlink_parent(tmp_path: Path) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(routing.RoutingPolicyError, match="parent"):
        routing.persist_record(alias / "route.json", record)
    assert list(actual_parent.iterdir()) == []


def test_routing_record_persistence_rejects_intermediate_symlink_parent(
    tmp_path: Path,
) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    actual_parent = tmp_path / "actual"
    nested = actual_parent / "nested"
    nested.mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(routing.RoutingPolicyError, match="symlink component"):
        routing.persist_record(alias / "nested" / "route.json", record)
    assert list(nested.iterdir()) == []


def test_routing_record_persistence_rejects_writable_parent(tmp_path: Path) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    parent = tmp_path / "writable"
    parent.mkdir()
    parent.chmod(0o777)
    try:
        with pytest.raises(routing.RoutingPolicyError, match="writable by group or other"):
            routing.persist_record(parent / "route.json", record)
        assert list(parent.iterdir()) == []
    finally:
        parent.chmod(0o700)


def test_routing_record_persistence_rejects_writable_existing_record(
    tmp_path: Path,
) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    target = tmp_path / "route.json"
    target.write_bytes(routing.canonical_record(record))
    target.chmod(0o666)

    with pytest.raises(routing.RoutingPolicyError, match="writable by group or other"):
        routing.persist_record(target, record)


def test_routing_record_persistence_rejects_parent_traversal(tmp_path: Path) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())

    with pytest.raises(routing.RoutingPolicyError, match="parent traversal"):
        routing.persist_record(tmp_path / "child" / ".." / "route.json", record)


def test_routing_record_persistence_rejects_symlink_target(tmp_path: Path) -> None:
    record = routing.route_alert(_alert(), main_sha=MAIN, config=_config())
    actual = tmp_path / "actual.json"
    actual.write_text("do not replace", encoding="utf-8")
    link = tmp_path / "route.json"
    link.symlink_to(actual)

    with pytest.raises(routing.RoutingPolicyError, match="regular file"):
        routing.persist_record(link, record)
    assert actual.read_text(encoding="utf-8") == "do not replace"
