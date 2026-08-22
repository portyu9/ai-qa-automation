from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ai_qa_automation import telemetry
from ai_qa_automation.runtime import journal as journal_module
from ai_qa_automation.runtime.journal import RunJournal


class _FakeCounter:
    def __init__(self) -> None:
        self.calls: list[tuple[int | float, dict[str, str]]] = []

    def add(self, value: int | float, attributes: dict[str, str]) -> None:
        self.calls.append((value, dict(attributes)))


class _FakeHistogram:
    def __init__(self) -> None:
        self.calls: list[tuple[int | float, dict[str, str]]] = []

    def record(self, value: int | float, attributes: dict[str, str]) -> None:
        self.calls.append((value, dict(attributes)))


def _fake_instruments() -> dict[str, Any]:
    return {
        "runs": _FakeCounter(),
        "duration": _FakeHistogram(),
        "tool_calls": _FakeHistogram(),
        "tool_events": _FakeCounter(),
        "policy_denials": _FakeCounter(),
        "mcp_outcomes": _FakeCounter(),
    }


def test_run_metrics_are_low_cardinality_and_ignore_invalid_measurements(monkeypatch: Any) -> None:
    instruments = _fake_instruments()
    monkeypatch.setattr(telemetry, "_metric_instruments", lambda: instruments)

    telemetry.record_run_metrics(
        terminal_status="SUCCESS",
        duration_seconds=2.5,
        tool_calls=7,
    )
    telemetry.record_run_metrics(
        terminal_status="surprise-provider-value",
        duration_seconds=float("nan"),
        tool_calls=-1,
    )

    runs = instruments["runs"].calls
    assert runs == [
        (1, {"terminal.status": "SUCCESS"}),
        (1, {"terminal.status": "NOT_VERIFIED"}),
    ]
    assert instruments["duration"].calls == [(2.5, {"terminal.status": "SUCCESS"})]
    assert instruments["tool_calls"].calls == [(7.0, {"terminal.status": "SUCCESS"})]
    assert all("run_id" not in attributes for _, attributes in runs)
    assert all("objective" not in attributes for _, attributes in runs)


def test_tool_policy_and_mcp_metrics_use_bounded_labels(monkeypatch: Any) -> None:
    instruments = _fake_instruments()
    monkeypatch.setattr(telemetry, "_metric_instruments", lambda: instruments)

    telemetry.record_tool_event("mcp__qa__run_pytest", "requested")
    telemetry.record_tool_event("mcp__github__get_issue", "failed")
    telemetry.record_tool_event("attacker-controlled-tool-name", "succeeded")
    telemetry.record_policy_denial("workspace_integrity")
    telemetry.record_policy_denial("attacker-controlled-category")
    telemetry.record_mcp_outcome("github", "UNAUTHORIZED")
    telemetry.record_mcp_outcome("attacker-provider", "attacker-outcome")

    assert instruments["tool_events"].calls == [
        (1, {"tool.surface": "internal_qa", "tool.outcome": "requested"}),
        (1, {"tool.surface": "github_mcp", "tool.outcome": "failed"}),
        (1, {"tool.surface": "other", "tool.outcome": "succeeded"}),
    ]
    assert instruments["policy_denials"].calls == [
        (1, {"policy.category": "workspace_integrity"}),
        (1, {"policy.category": "other"}),
    ]
    assert instruments["mcp_outcomes"].calls == [
        (1, {"mcp.provider": "github", "mcp.outcome": "UNAUTHORIZED"}),
        (1, {"mcp.provider": "other", "mcp.outcome": "FAILED"}),
    ]


def test_structured_run_finish_event_records_metrics_without_sensitive_labels(
    monkeypatch: Any, caplog: Any
) -> None:
    instruments = _fake_instruments()
    monkeypatch.setattr(telemetry, "_metric_instruments", lambda: instruments)
    logger = logging.getLogger("telemetry-test")

    with caplog.at_level(logging.INFO, logger=logger.name):
        telemetry.emit_event(
            logger,
            "agent_run_finished",
            run_id="run-secret-cardinality",
            terminal_status="BLOCKED",
            duration_seconds=1.25,
            tool_calls=3,
        )

    payload = json.loads(caplog.records[-1].message)
    assert payload["run_id"] == "run-secret-cardinality"
    assert instruments["runs"].calls == [(1, {"terminal.status": "BLOCKED"})]
    assert instruments["duration"].calls == [(1.25, {"terminal.status": "BLOCKED"})]
    assert instruments["tool_calls"].calls == [(3.0, {"terminal.status": "BLOCKED"})]


def test_journal_projects_metrics_only_after_durable_event_and_metrics_are_fail_soft(
    tmp_path: Path, monkeypatch: Any
) -> None:
    observed: list[tuple[str, str]] = []

    monkeypatch.setattr(
        journal_module,
        "record_tool_event",
        lambda tool, outcome: observed.append((tool, outcome)),
    )
    monkeypatch.setattr(
        journal_module,
        "record_policy_denial",
        lambda category: observed.append(("policy", category)),
    )
    monkeypatch.setattr(
        journal_module,
        "record_mcp_outcome",
        lambda provider, outcome: observed.append((provider, outcome)),
    )

    journal = RunJournal(tmp_path / "journal.jsonl")
    first_hash = journal.append("tool_requested", tool_name="mcp__qa__run_pytest")
    journal.append("policy_denied", tool_name="mcp__qa__create_test_file", reason="blocked")
    journal.append("tool_completed", tool_name="mcp__github__get_issue", failed=False)

    assert len(first_hash) == 64
    assert observed == [
        ("mcp__qa__run_pytest", "requested"),
        ("mcp__qa__create_test_file", "denied"),
        ("policy", "deterministic_policy"),
        ("mcp__github__get_issue", "succeeded"),
        ("github", "AVAILABLE"),
    ]
    assert journal.verify()["valid"] is True

    monkeypatch.setattr(
        journal_module,
        "record_tool_event",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("metrics unavailable")),
    )
    second_hash = journal.append("tool_requested", tool_name="mcp__qa__inspect_repository")

    assert len(second_hash) == 64
    assert journal.verify() == {
        "valid": True,
        "events": 4,
        "head_hash": second_hash,
    }
