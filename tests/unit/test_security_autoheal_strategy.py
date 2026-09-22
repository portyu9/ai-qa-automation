from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SECURITY_SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"
SCRIPT_DIR = SECURITY_SCRIPT.parent


def _load_security_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_autoheal_strategy_test", SECURITY_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT_DIR))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT_DIR))
    return module


autoheal = _load_security_autoheal()


def _closed_repair(metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "user": {
            "login": autoheal.GITHUB_ACTIONS_LOGIN,
            "id": autoheal.GITHUB_ACTIONS_USER_ID,
        },
        "head": {"ref": "automation/codeql-autoheal-7-abcdef123456"},
        "body": autoheal._marker(metadata),
    }


class _ClosedRepairApi:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, int]] = []

    def list_all(self, path: str, *, max_pages: int = 10) -> list[dict[str, Any]]:
        self.calls.append((path, max_pages))
        return self.rows


def test_reflective_xss_uses_literal_only_deterministic_strategy() -> None:
    subject = {
        "number": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "line": 1,
    }

    assert autoheal._repair_strategy(subject) == autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    repaired = autoheal._deterministic_repair(subject)

    assert repaired is not None
    assert "\nimport json\n" not in repaired
    assert "json.dumps(safe_mode)" not in repaired
    for value in (
        "pass",
        "app-defect",
        "outdated-locator",
        "api-failure",
        "timing",
        "invalid-data",
        "prompt-injection",
    ):
        assert f"mode_js = '\"{value}\"'" in repaired
    compile(repaired, "examples/reference_sut/app.py", "exec")


def test_legacy_copilot_attempts_do_not_consume_new_deterministic_epoch() -> None:
    legacy = {
        "version": 1,
        "alert": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "generator": "github-codeql-autofix",
    }
    api = _ClosedRepairApi([_closed_repair(legacy), _closed_repair({**legacy, "attempt": 2})])

    assert autoheal._attempt_count(api, 7, autoheal.MODEL_AUTOFIX_STRATEGY) == 2
    assert (
        autoheal._attempt_count(api, 7, autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY)
        == 0
    )
    assert api.calls == [
        ("/pulls?state=closed&sort=updated&direction=desc", 10),
        ("/pulls?state=closed&sort=updated&direction=desc", 10),
    ]


def test_explicit_strategy_attempt_is_counted_only_in_its_epoch() -> None:
    deterministic = {
        "version": 1,
        "alert": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
        "generator": "deterministic",
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    api = _ClosedRepairApi([_closed_repair(deterministic)])

    assert (
        autoheal._attempt_count(api, 7, autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY)
        == 1
    )
    assert autoheal._attempt_count(api, 7, autoheal.MODEL_AUTOFIX_STRATEGY) == 0


def test_strategy_binding_rejects_legacy_model_strategy_after_deterministic_upgrade() -> None:
    subject = {
        "number": 7,
        "rule": "py/reflective-xss",
        "path": "examples/reference_sut/app.py",
    }
    legacy_model = {
        "alert": 7,
        "rule": subject["rule"],
        "path": subject["path"],
        "generator": "github-codeql-autofix",
    }

    with pytest.raises(autoheal.PolicyBlock, match="strategy drifted"):
        autoheal._require_strategy_binding(legacy_model, subject)

    deterministic = {
        **legacy_model,
        "generator": "deterministic",
        "strategy": autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
    }
    assert (
        autoheal._require_strategy_binding(deterministic, subject)
        == autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY
    )


def test_legacy_deterministic_marker_infers_code_owned_strategy() -> None:
    metadata = {
        "alert": 9,
        "rule": "py/overly-permissive-file",
        "path": "tests/unit/test_example.py",
        "generator": "deterministic",
    }

    assert autoheal._marker_strategy(metadata) == autoheal.OVERLY_PERMISSIVE_TEST_STRATEGY
