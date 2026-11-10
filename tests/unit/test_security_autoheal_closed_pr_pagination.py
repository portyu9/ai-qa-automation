"""Closed-PR recovery must not lose older CodeQL repair provenance to repo growth."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "security_autoheal.py"


def _load_autoheal() -> ModuleType:
    spec = importlib.util.spec_from_file_location("security_autoheal_pagination_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SCRIPT.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SCRIPT.parent))
    return module


autoheal = _load_autoheal()
CLOSED_PATH = "/pulls?state=closed&sort=updated&direction=desc"


class _PagedClosedPulls(autoheal.GitHubApi):
    """Deterministic server-side pagination fixture; no network or mutation."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.pages: list[int] = []

    def get(self, path: str) -> list[dict[str, Any]]:
        assert path.startswith(f"{CLOSED_PATH}&per_page=")
        query = parse_qs(path.split("?", 1)[1])
        page = int(query["page"][0])
        per_page = int(query["per_page"][0])
        assert per_page == 100
        assert page == len(self.pages) + 1
        self.pages.append(page)
        start = (page - 1) * per_page
        return [
            {
                "number": index + 1,
                "state": "closed",
                "merged_at": None,
                "user": {"login": "unrelated-owner"},
            }
            for index in range(start, min(start + per_page, self.count))
        ]


def test_terminal_recovery_reads_past_four_full_pages() -> None:
    api = _PagedClosedPulls(401)
    assert autoheal._current_main_merged_repair(api, "f" * 40) is None
    assert api.pages == [1, 2, 3, 4, 5]


def test_attempt_accounting_reads_past_ten_full_pages() -> None:
    api = _PagedClosedPulls(1001)
    assert (
        autoheal._attempt_count(
            api,
            7,
            autoheal.REFERENCE_SUT_REFLECTIVE_XSS_STRATEGY,
            "f" * 40,
        )
        == 0
    )
    assert api.pages == list(range(1, 12))


def test_pagination_still_fails_closed_on_true_exhaustion() -> None:
    api = _PagedClosedPulls(201)
    with pytest.raises(autoheal.AutohealError, match="pagination limit reached"):
        api.list_all(CLOSED_PATH, max_pages=2)
    assert api.pages == [1, 2]
