"""Execute the reviewed native wake jq filter against authenticated-shape fixtures.

Static source checks also run elsewhere. These prove the actual jq expression
accepts only expected scheduled GitHub Actions runs, without any API writes.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
WAKE = ROOT / ".github/workflows/current-main-ci-wake.yml"
SHA = "a" * 40
REPOSITORY = "portyu9/ai-qa-automation"
NOW = int(datetime(2026, 10, 26, 16, 30, tzinfo=timezone.utc).timestamp())
SOURCES = (
    (
        346203190,
        "Trusted PR Auto Gate — ƳƤ AI QA Automation Framework",
        ".github/workflows/trusted-pr-auto.yml",
    ),
    (
        372619559,
        "Ruleset Reconciler — ƳƤ AI QA Automation Framework",
        ".github/workflows/ruleset-reconciler.yml",
    ),
)


def native_filter() -> str:
    source = WAKE.read_text(encoding="utf-8")
    begin = """                --argjson now "$now_utc" '"""
    end = """' <<< "$wake_json" > /dev/null"""
    assert source.count(begin) == 1
    assert source.count(end) == 1
    return source.split(begin, 1)[1].split(end, 1)[0]


def fixture(source_index: int = 0) -> dict[str, object]:
    workflow_id, name, path = SOURCES[source_index]
    return {
        "id": 123,
        "workflow_id": workflow_id,
        "name": name,
        "path": path,
        "event": "schedule",
        "head_sha": SHA,
        "head_branch": "main",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "check_suite_id": 456,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-26T16:15:00Z",
    }


def admitted(record: dict[str, object]) -> bool:
    assert shutil.which("jq"), "the trusted runner must provide native jq"
    args = [
        "jq",
        "-e",
        "--arg",
        "repo",
        REPOSITORY,
        "--arg",
        "sha",
        SHA,
        "--argjson",
        "run",
        "123",
        "--argjson",
        "now",
        str(NOW),
        native_filter(),
    ]
    result = subprocess.run(
        args,
        input=json.dumps(record),
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.parametrize("source_index", [0, 1])
def test_authentic_scheduled_source_is_admitted(source_index: int) -> None:
    assert admitted(fixture(source_index))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("id", 124),
        ("workflow_id", 111),
        ("name", "Untrusted source"),
        ("path", ".github/workflows/untrusted.yml"),
        ("event", "pull_request"),
        ("head_sha", "b" * 40),
        ("head_branch", "feature/spoof"),
        ("repository", {"full_name": "attacker/fork"}),
        ("head_repository", {"full_name": "attacker/fork"}),
        ("check_suite_id", 0),
        ("run_attempt", 2),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("created_at", "2026-10-26T09:00:00Z"),
    ],
)
def test_spoofed_or_stale_native_source_is_rejected(
    field: str, replacement: object
) -> None:
    record = fixture()
    record[field] = replacement
    assert not admitted(record)
