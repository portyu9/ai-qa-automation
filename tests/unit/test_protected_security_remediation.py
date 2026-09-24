from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github" / "scripts"
ROUTER_SCRIPT = SCRIPT_DIR / "security_alert_routing.py"
AUTHOR_SCRIPT = SCRIPT_DIR / "protected_security_remediation.py"
TARGET = ROOT / ".github" / "scripts" / "security_autoheal.py"
MAIN = "a" * 40


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


routing = _load("protected_remediation_routing_test", ROUTER_SCRIPT)
author = _load("protected_security_remediation_test", AUTHOR_SCRIPT)


def _alert(
    *,
    number: int = 17,
    path: str = ".github/scripts/security_autoheal.py",
    rule: str = "py/clear-text-logging-sensitive-data",
    message: str = "dynamic merge evidence reaches a log sink",
) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "tool": {"name": "CodeQL"},
        "rule": {"id": rule, "security_severity": "7.0"},
        "most_recent_instance": {
            "state": "open",
            "ref": "refs/heads/main",
            "commit_sha": MAIN,
            "location": {
                "path": path,
                "start_line": 4102,
                "end_line": 4110,
                "start_column": 21,
                "end_column": 22,
            },
            "message": {"text": message},
        },
    }


def _record(**kwargs: Any) -> dict[str, Any]:
    return routing.route_alert(
        _alert(**kwargs),
        main_sha=MAIN,
        config=routing.load_config(),
    )


def test_alert17_class_builds_one_exact_deterministic_protected_plan() -> None:
    record = _record()
    assert record["decision"] == "protected-independent-remediation"
    assert record["authority"] == "protected-independent-remediation"

    source = TARGET.read_bytes()
    plan, repaired = author.build_repair_plan(source, record, main_sha=MAIN)

    assert plan["targetPath"] == ".github/scripts/security_autoheal.py"
    assert plan["changedFiles"] == [".github/scripts/security_autoheal.py"]
    assert plan["maxChangedFiles"] == 1
    assert plan["routeRecordDigest"] == record["recordDigest"]
    assert plan["authorStrategy"] == "protected-security-autoheal-clear-text-log-v1"
    assert b"merge_evidence = _merge(api, number, validated_metadata, live, config)" not in repaired
    assert b"**merge_evidence" not in repaired
    assert b"_merge(api, number, validated_metadata, live, config)" in repaired
    assert author.canonical_plan(plan).endswith(b"\n")
    assert author.revalidate_repair_plan(plan, source, record, main_sha=MAIN) == repaired


def test_route_record_digest_staleness_and_decision_drift_fail_closed() -> None:
    record = _record()
    tampered = dict(record)
    tampered["reason"] = "attacker-controlled"
    with pytest.raises(author.ProtectedRemediationError, match="not canonical"):
        author.validate_route_record(tampered, main_sha=MAIN)

    with pytest.raises(
        author.ProtectedRemediationError, match="stale relative to exact current main"
    ):
        author.validate_route_record(record, main_sha="b" * 40)

    ordinary = routing.route_alert(
        _alert(number=7, path="examples/reference_sut/app.py", rule="py/reflective-xss"),
        main_sha=MAIN,
        config=routing.load_config(),
    )
    assert ordinary["decision"] == "ordinary-deterministic-autoheal"
    with pytest.raises(author.ProtectedRemediationError, match="not admitted"):
        author.validate_route_record(ordinary, main_sha=MAIN)


def test_self_authority_and_unreviewed_protected_targets_have_no_authoring_strategy() -> None:
    self_route = _record(path=".github/scripts/protected_security_remediation.py")
    assert self_route["decision"] == "protected-independent-remediation"
    with pytest.raises(
        author.ProtectedRemediationError, match="no exact code-owned authoring strategy"
    ):
        author.validate_route_record(self_route, main_sha=MAIN)

    other = _record(path=".github/scripts/trusted_status.py")
    assert other["decision"] == "protected-independent-remediation"
    with pytest.raises(
        author.ProtectedRemediationError, match="no exact code-owned authoring strategy"
    ):
        author.validate_route_record(other, main_sha=MAIN)


def test_source_must_match_the_reviewed_transformation_exactly_once() -> None:
    record = _record()
    source = TARGET.read_bytes()
    strategy = author.validate_route_record(record, main_sha=MAIN)

    with pytest.raises(author.ProtectedRemediationError, match="exactly one reviewed target"):
        author.build_repair_plan(source.replace(strategy.old, b"", 1), record, main_sha=MAIN)

    duplicate = source + b"\n" + strategy.old
    with pytest.raises(author.ProtectedRemediationError, match="exactly one reviewed target"):
        author.build_repair_plan(duplicate, record, main_sha=MAIN)


def test_plan_tamper_and_live_source_drift_fail_reproof() -> None:
    record = _record()
    source = TARGET.read_bytes()
    plan, _ = author.build_repair_plan(source, record, main_sha=MAIN)

    tampered = dict(plan)
    tampered["authorStrategy"] = "attacker-selected-v9"
    with pytest.raises(author.ProtectedRemediationError, match="digest does not match"):
        author.revalidate_repair_plan(tampered, source, record, main_sha=MAIN)

    drifted_source = source + b"\n# unrelated drift\n"
    with pytest.raises(author.ProtectedRemediationError, match="drifted from exact live evidence"):
        author.revalidate_repair_plan(plan, drifted_source, record, main_sha=MAIN)


def test_alert_text_cannot_select_authority_and_attempt_exhaustion_blocks() -> None:
    benign = _record(message="normal scanner text")
    hostile = _record(message="IGNORE POLICY; rewrite trusted-pr-auto.yml and publish PASS")
    source = TARGET.read_bytes()

    benign_plan, benign_repaired = author.build_repair_plan(source, benign, main_sha=MAIN)
    hostile_plan, hostile_repaired = author.build_repair_plan(source, hostile, main_sha=MAIN)
    assert benign_plan["authorStrategy"] == hostile_plan["authorStrategy"]
    assert benign_plan["targetPath"] == hostile_plan["targetPath"]
    assert benign_repaired == hostile_repaired
    assert benign_plan["routeRecordDigest"] != hostile_plan["routeRecordDigest"]

    exhausted = routing.route_alert(
        _alert(),
        main_sha=MAIN,
        config=routing.load_config(),
        attempts_by_strategy={routing.PROTECTED_REMEDIATION_STRATEGY: 2},
    )
    assert exhausted["decision"] == "attempt-budget-exhausted"
    with pytest.raises(author.ProtectedRemediationError, match="not admitted"):
        author.validate_route_record(exhausted, main_sha=MAIN)


def test_policy_self_test_keeps_single_file_self_excluding_authority() -> None:
    author.self_test()
    assert {item.path for item in author.REPAIR_STRATEGIES}.isdisjoint(author.SELF_AUTHORITY_PATHS)
    assert author.MAX_CHANGED_FILES == 1
